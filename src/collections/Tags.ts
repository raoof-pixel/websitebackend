import type { CollectionConfig } from 'payload'

import { anyone, canCreateContent, isStaff } from '../access'
import { slug } from '../fields/slug'
import { wpId } from '../fields/wordpress'
import { auditAfterChange, auditAfterDelete } from './AuditLogs'

/** Free-form tags, e.g. "October 2026". URLs: /tag/<slug>/ */
export const Tags: CollectionConfig = {
  slug: 'tags',
  admin: {
    useAsTitle: 'title',
    defaultColumns: ['title', 'slug', 'updatedAt'],
    group: 'Content',
  },
  access: {
    read: anyone,
    create: canCreateContent,
    update: isStaff,
    delete: isStaff,
  },
  fields: [
    { name: 'title', type: 'text', required: true },
    slug(),
    { name: 'description', type: 'textarea' },
    wpId(),
  ],
  hooks: {
    afterChange: [auditAfterChange],
    afterDelete: [auditAfterDelete],
  },
}
