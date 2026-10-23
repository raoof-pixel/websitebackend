import type { Access, FieldAccess, PayloadRequest } from 'payload'

export type Role = 'admin' | 'editor' | 'author' | 'automation'

export const ROLES: { label: string; value: Role }[] = [
  { label: 'Admin — everything, including users and settings', value: 'admin' },
  { label: 'Editor — all content, any author', value: 'editor' },
  { label: 'Author — own articles only', value: 'author' },
  { label: 'Automation — API key for scripts (e.g. Newswire)', value: 'automation' },
]

type UserLike = { id?: number | string; roles?: Role[] | null; collection?: string } | null | undefined

export const hasRole = (user: UserLike, ...roles: Role[]): boolean =>
  Boolean(user && Array.isArray(user.roles) && user.roles.some((r) => roles.includes(r)))

const userOf = (req: PayloadRequest): UserLike => req.user as UserLike

export const anyone: Access = () => true

export const authenticated: Access = ({ req }) => Boolean(req.user)

export const isAdmin: Access = ({ req }) => hasRole(userOf(req), 'admin')

export const isAdminFieldLevel: FieldAccess = ({ req }) => hasRole(userOf(req), 'admin')

export const isStaff: Access = ({ req }) => hasRole(userOf(req), 'admin', 'editor')

/** Admins, editors and automation keys can manage all content. */
export const canManageAllContent = (req: PayloadRequest) =>
  hasRole(userOf(req), 'admin', 'editor', 'automation')

/** Anyone logged in can create content (authors included). */
export const canCreateContent: Access = ({ req }) =>
  hasRole(userOf(req), 'admin', 'editor', 'author', 'automation')

/**
 * Update/delete: staff can touch everything; authors only documents they created.
 */
export const canEditOwnOrAll: Access = ({ req }) => {
  const user = userOf(req)
  if (!user) return false
  if (canManageAllContent(req)) return true
  if (hasRole(user, 'author')) {
    return { createdBy: { equals: user.id } }
  }
  return false
}

/** Public sees published docs only; logged-in staff see drafts too. */
export const publishedOrAuthenticated: Access = ({ req }) => {
  if (req.user) return true
  return { _status: { equals: 'published' } }
}
