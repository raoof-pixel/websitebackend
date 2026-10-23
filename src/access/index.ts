import type { Access, FieldAccess, PayloadRequest } from 'payload'

export type Role = 'admin' | 'editor' | 'author' | 'automation'

export const ROLES: { label: string; value: Role }[] = [
  { label: 'Admin — everything, including users and settings', value: 'admin' },
  { label: 'Editor — all articles and pages, any author', value: 'editor' },
  { label: 'Author — own articles only', value: 'author' },
  { label: 'Automation — API key only (e.g. Newswire); cannot log in or delete', value: 'automation' },
]

type UserLike = { id?: number | string; roles?: Role[] | null; collection?: string } | null | undefined

export const hasRole = (user: UserLike, ...roles: Role[]): boolean =>
  Boolean(user && Array.isArray(user.roles) && user.roles.some((r) => roles.includes(r)))

/** True when the only role is Automation (an API-key bot). */
export const isAutomationOnly = (user: UserLike) =>
  Boolean(user && Array.isArray(user.roles) && user.roles.length > 0 && user.roles.every((r) => r === 'automation'))

const userOf = (req: PayloadRequest): UserLike => req.user as UserLike

export const anyone: Access = () => true

export const authenticated: Access = ({ req }) => Boolean(req.user)

export const authenticatedField: FieldAccess = ({ req }) => Boolean(req.user)

export const isAdmin: Access = ({ req }) => hasRole(userOf(req), 'admin')

export const isAdminFieldLevel: FieldAccess = ({ req }) => hasRole(userOf(req), 'admin')

export const isStaff: Access = ({ req }) => hasRole(userOf(req), 'admin', 'editor')

/** Anyone with a content role can create content. */
export const canCreateContent: Access = ({ req }) =>
  hasRole(userOf(req), 'admin', 'editor', 'author', 'automation')

/**
 * Update: admins/editors everything; automation everything it may create (articles);
 * authors only documents they created themselves.
 */
export const canUpdateOwnOrAll: Access = ({ req }) => {
  const user = userOf(req)
  if (!user) return false
  if (hasRole(user, 'admin', 'editor', 'automation')) return true
  if (hasRole(user, 'author')) return { createdBy: { equals: user.id } }
  return false
}

/**
 * Delete: admins/editors everything; authors their own; automation never
 * (a leaked API key must not be able to wipe content).
 */
export const canDeleteOwnOrAll: Access = ({ req }) => {
  const user = userOf(req)
  if (!user) return false
  if (hasRole(user, 'admin', 'editor')) return true
  if (hasRole(user, 'author')) return { createdBy: { equals: user.id } }
  return false
}

/** Public sees published docs only; logged-in staff see drafts too. */
export const publishedOrAuthenticated: Access = ({ req }) => {
  if (req.user) return true
  return { _status: { equals: 'published' } }
}
