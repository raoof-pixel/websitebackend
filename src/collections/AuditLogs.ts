import type {
  CollectionAfterChangeHook,
  CollectionAfterDeleteHook,
  CollectionConfig,
  PayloadRequest,
} from 'payload'

import { isAdmin } from '../access'

/**
 * Tamper-proof activity log: who logged in (or failed to), and who created, changed, published
 * or deleted what. Nobody can edit or delete entries through the admin panel or the API,
 * not even an admin, so an intruder can't cover their tracks.
 */
export const AuditLogs: CollectionConfig = {
  slug: 'audit-logs',
  labels: { singular: 'Activity log entry', plural: 'Activity log' },
  admin: {
    group: 'Admin',
    useAsTitle: 'summary',
    defaultColumns: ['createdAt', 'action', 'summary', 'userEmail', 'ip'],
    description: 'Read-only record of logins and content changes.',
  },
  access: {
    read: isAdmin,
    create: () => false, // only written internally with overrideAccess
    update: () => false,
    delete: () => false,
  },
  fields: [
    {
      name: 'action',
      type: 'select',
      required: true,
      index: true,
      options: ['login', 'login-failed', 'logout', 'create', 'update', 'publish', 'unpublish', 'delete'],
    },
    { name: 'summary', type: 'text' },
    { name: 'collection', type: 'text', index: true },
    { name: 'docId', type: 'text', index: true },
    { name: 'user', type: 'relationship', relationTo: 'users' },
    { name: 'userEmail', type: 'text', index: true },
    { name: 'ip', type: 'text' },
    { name: 'userAgent', type: 'text' },
  ],
  timestamps: true,
}

export const clientIp = (req: PayloadRequest): string => {
  const h = req.headers
  return (
    h.get('x-real-ip') ||
    h.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    h.get('cf-connecting-ip') ||
    ''
  )
}

type Entry = {
  action: string
  summary?: string
  collection?: string
  docId?: number | string
  userId?: number | string | null
  userEmail?: string | null
}

export const writeAudit = async (req: PayloadRequest, entry: Entry) => {
  if (req.context?.fromImport) return // bulk imports would flood the log
  try {
    const user = req.user as { id?: number | string; email?: string; collection?: string } | null
    await req.payload.create({
      collection: 'audit-logs',
      overrideAccess: true,
      req,
      data: {
        action: entry.action,
        summary: entry.summary?.slice(0, 300),
        collection: entry.collection,
        docId: entry.docId !== undefined ? String(entry.docId) : undefined,
        user: (entry.userId ?? (user?.collection === 'users' ? user?.id : undefined)) as any,
        userEmail: entry.userEmail ?? user?.email ?? null,
        ip: clientIp(req),
        userAgent: req.headers.get('user-agent')?.slice(0, 300) || '',
      } as any,
    })
  } catch (err) {
    req.payload.logger.error(`Audit log write failed: ${(err as Error).message}`)
  }
}

const label = (doc: any) => doc?.title || doc?.name || doc?.email || doc?.slug || doc?.id

/** Attach to any collection to log its changes. */
export const auditAfterChange: CollectionAfterChangeHook = async ({ collection, doc, operation, previousDoc, req }) => {
  let action: string = operation
  if (doc?._status === 'published' && previousDoc?._status !== 'published') action = 'publish'
  else if (previousDoc?._status === 'published' && doc?._status === 'draft' && operation === 'update') {
    // Saving a draft over a published doc keeps it live; only log a real unpublish.
    action = 'update'
  }
  // Skip autosave noise.
  if (operation === 'update' && doc?._status === 'draft' && req.query?.autosave === 'true') return doc
  await writeAudit(req, {
    action,
    collection: collection.slug,
    docId: doc?.id,
    summary: `${action} ${collection.slug}: ${label(doc)}`,
  })
  return doc
}

export const auditAfterDelete: CollectionAfterDeleteHook = async ({ collection, doc, req }) => {
  await writeAudit(req, {
    action: 'delete',
    collection: collection.slug,
    docId: doc?.id,
    summary: `delete ${collection.slug}: ${label(doc)}`,
  })
  return doc
}
