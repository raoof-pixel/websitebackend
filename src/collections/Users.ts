import { APIError } from 'payload'
import type { CollectionConfig } from 'payload'

import { hasRole, isAdmin, isAdminFieldLevel, isAutomationOnly, ROLES } from '../access'
import { auditAfterChange, auditAfterDelete, writeAudit } from './AuditLogs'

/** Password rules: 12+ characters with upper case, lower case, a number and a symbol. */
export const passwordProblem = (pw: unknown): string | null => {
  if (typeof pw !== 'string') return null
  if (pw.length < 12) return 'Password must be at least 12 characters.'
  if (pw.length > 128) return 'Password must be at most 128 characters.'
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw) || !/[^A-Za-z0-9]/.test(pw)) {
    return 'Password must include upper-case and lower-case letters, a number and a symbol.'
  }
  if (/(password|canadiansme|qwerty|123456|letmein|admin)/i.test(pw)) {
    return 'Password is too easy to guess.'
  }
  return null
}

const isProd = process.env.NODE_ENV === 'production'

/**
 * Staff logins for the admin panel (not public bylines — see the Authors collection).
 * API keys can be enabled per user, e.g. a dedicated "Newswire bot" user with only the
 * Automation role, so scripts can create articles through the REST API.
 */
export const Users: CollectionConfig = {
  slug: 'users',
  admin: {
    useAsTitle: 'name',
    defaultColumns: ['name', 'email', 'roles', 'updatedAt'],
    group: 'Admin',
  },
  auth: {
    useAPIKey: true,
    tokenExpiration: 60 * 60 * 8, // log out after 8 hours
    maxLoginAttempts: 5, // then the account is locked...
    lockTime: 30 * 60 * 1000, // ...for 30 minutes
    useSessions: true, // logins can be revoked server-side
    removeTokenFromResponses: true, // token only travels in the HttpOnly cookie
    cookies: {
      secure: isProd,
      sameSite: 'Lax',
    },
    forgotPassword: {
      expiration: 30 * 60 * 1000, // reset links expire after 30 minutes
    },
  },
  access: {
    // Bots (automation-only users) can never open the admin panel.
    admin: ({ req }) => Boolean(req.user) && !isAutomationOnly(req.user as never),
    create: isAdmin,
    delete: isAdmin,
    read: ({ req }) => {
      if (!req.user) return false
      if (hasRole(req.user as never, 'admin')) return true
      return { id: { equals: req.user.id } }
    },
    update: ({ req }) => {
      if (!req.user) return false
      if (hasRole(req.user as never, 'admin')) return true
      return { id: { equals: req.user.id } }
    },
    unlock: isAdmin,
  },
  fields: [
    { name: 'name', type: 'text', required: true },
    {
      name: 'roles',
      type: 'select',
      hasMany: true,
      required: true,
      defaultValue: ['author'],
      options: ROLES,
      saveToJWT: true,
      access: {
        // Only admins can change roles (prevents anyone promoting themselves).
        create: isAdminFieldLevel,
        update: isAdminFieldLevel,
      },
      admin: {
        description: 'Admins manage everything; Editors manage all articles; Authors only their own.',
      },
    },
    {
      name: 'author',
      type: 'relationship',
      relationTo: 'authors',
      admin: {
        description: 'Public byline for this person. New articles they create get this author by default.',
      },
    },
  ],
  hooks: {
    beforeOperation: [
      // Enforce the password policy on sign-up, password change and password reset.
      ({ args, operation }) => {
        if (['create', 'update', 'resetPassword'].includes(operation)) {
          const problem = passwordProblem((args as { data?: { password?: unknown } })?.data?.password)
          if (problem) throw new APIError(problem, 400, undefined, true)
        }
        return args
      },
    ],
    beforeChange: [
      async ({ data, operation, req, originalDoc }) => {
        if (operation === 'create') {
          // The very first account is always an admin; afterwards nobody can self-register
          // (create access is admin-only).
          const { totalDocs } = await req.payload.count({ collection: 'users', overrideAccess: true, req })
          if (totalDocs === 0) data.roles = ['admin']
        }
        // Only admins can turn on, change or remove API keys. Otherwise a stolen login cookie could be
        // turned into a permanent key that survives logout and lockout.
        if (operation === 'update' && !hasRole(req.user as never, 'admin')) {
          for (const k of ['enableAPIKey', 'apiKey', 'apiKeyIndex'] as const) {
            if (k in data) {
              if (originalDoc && k in originalDoc) data[k] = originalDoc[k]
              else delete data[k]
            }
          }
        }
        // Never let the last admin lose the admin role (avoids locking everyone out).
        if (operation === 'update' && hasRole(originalDoc, 'admin') && Array.isArray(data.roles) && !data.roles.includes('admin')) {
          const { totalDocs } = await req.payload.count({
            collection: 'users',
            where: { roles: { contains: 'admin' } },
            overrideAccess: true,
            req,
          })
          if (totalDocs <= 1) throw new APIError('You cannot remove the last admin.', 400, undefined, true)
        }
        return data
      },
    ],
    beforeLogin: [
      ({ user }) => {
        if (isAutomationOnly(user)) {
          throw new APIError('This account can only be used with an API key.', 403, undefined, true)
        }
        return user
      },
    ],
    afterLogin: [
      async ({ req, user }) => {
        await writeAudit(req, { action: 'login', userId: user.id, userEmail: user.email, summary: `login ${user.email}` })
      },
    ],
    afterLogout: [
      async ({ req }) => {
        await writeAudit(req, { action: 'logout', summary: 'logout' })
      },
    ],
    afterError: [
      async ({ error, req }) => {
        const path = (() => {
          try {
            return new URL(req.url || '', 'http://x').pathname
          } catch {
            return ''
          }
        })()
        if (path.endsWith('/users/login')) {
          const email = typeof (req.data as any)?.email === 'string' ? (req.data as any).email.slice(0, 200) : ''
          await writeAudit(req, {
            action: 'login-failed',
            userId: null,
            userEmail: email,
            summary: `failed login ${email}: ${error.message}`.slice(0, 300),
          })
        }
      },
    ],
    afterChange: [auditAfterChange],
    afterDelete: [auditAfterDelete],
  },
  timestamps: true,
}
