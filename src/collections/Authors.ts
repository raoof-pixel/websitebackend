import type { CollectionConfig } from 'payload'

import { anyone, canCreateContent, isStaff } from '../access'
import { slug } from '../fields/slug'
import { wpId } from '../fields/wordpress'
import { auditAfterChange, auditAfterDelete } from './AuditLogs'
import { notifyFrontend, paths } from '../utilities/revalidate'

/**
 * Public bylines shown on articles and author pages (/author/<slug>/).
 * Separate from staff logins so guest contributors can have a byline without an account.
 */
export const Authors: CollectionConfig = {
  slug: 'authors',
  admin: {
    useAsTitle: 'name',
    defaultColumns: ['name', 'slug', 'jobTitle', 'updatedAt'],
    group: 'Content',
  },
  access: {
    read: anyone,
    create: canCreateContent,
    update: isStaff,
    delete: isStaff,
  },
  fields: [
    { name: 'name', type: 'text', required: true },
    slug('name'),
    { name: 'jobTitle', type: 'text' },
    { name: 'avatar', type: 'upload', relationTo: 'media' },
    { name: 'bio', type: 'textarea' },
    {
      name: 'links',
      type: 'group',
      fields: ['website', 'linkedin', 'x', 'instagram'].map((name) => ({
        name,
        type: 'text' as const,
        label: name === 'x' ? 'X (Twitter)' : undefined,
        validate: (v: unknown) =>
          !v || (typeof v === 'string' && /^https?:\/\//i.test(v)) ? true : 'Must start with https://',
      })),
    },
    wpId(),
  ],
  hooks: {
    afterChange: [
      async ({ doc, req }) => {
        await notifyFrontend(req, {
          collection: 'authors',
          event: 'change',
          id: doc.id,
          slug: doc.slug,
          paths: [paths.author(doc.slug)].filter(Boolean) as string[],
          tags: ['authors', `author:${doc.slug}`],
        })
        return doc
      },
      auditAfterChange,
    ],
    afterDelete: [auditAfterDelete],
  },
}
