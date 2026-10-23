import type { CollectionConfig } from 'payload'

import { hasRole, isAdmin, isAdminFieldLevel, ROLES } from '../access'

/**
 * Staff logins for the admin panel (not public bylines — see the Authors collection).
 * API keys can be enabled per user, e.g. a dedicated "Newswire bot" user with the
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
    tokenExpiration: 60 * 60 * 24 * 7, // 7 days
    maxLoginAttempts: 10,
    lockTime: 15 * 60 * 1000,
  },
  access: {
    // Only admins manage users; everyone else can read and update themselves.
    admin: ({ req }) => Boolean(req.user) && !hasRole(req.user as never, 'automation'),
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
  },
  fields: [
    {
      name: 'name',
      type: 'text',
      required: true,
    },
    {
      name: 'roles',
      type: 'select',
      hasMany: true,
      required: true,
      defaultValue: ['author'],
      options: ROLES,
      saveToJWT: true,
      access: {
        // Only admins can change roles (prevents self-promotion).
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
        description:
          'Public byline profile for this person. New articles they create get this author by default.',
      },
    },
  ],
  hooks: {
    beforeChange: [
      // The very first account created is always an admin.
      async ({ data, operation, req }) => {
        if (operation === 'create') {
          const { totalDocs } = await req.payload.count({ collection: 'users', overrideAccess: true })
          if (totalDocs === 0) data.roles = ['admin']
        }
        return data
      },
    ],
  },
  timestamps: true,
}
