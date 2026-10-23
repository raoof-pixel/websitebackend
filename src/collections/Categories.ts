import type { CollectionConfig } from 'payload'

import { anyone, isStaff } from '../access'
import { slug } from '../fields/slug'
import { wpId } from '../fields/wordpress'
import { notifyFrontend, paths } from '../utilities/revalidate'

/** Article sections, e.g. Latest News, Leadership, Interviews. URLs: /category/<slug>/ */
export const Categories: CollectionConfig = {
  slug: 'categories',
  admin: {
    useAsTitle: 'title',
    defaultColumns: ['title', 'slug', 'parent', 'showInMenu'],
    group: 'Content',
  },
  access: {
    read: anyone,
    create: isStaff,
    update: isStaff,
    delete: isStaff,
  },
  fields: [
    { name: 'title', type: 'text', required: true },
    slug(),
    {
      name: 'description',
      type: 'textarea',
      admin: { description: 'Intro text shown on the category page.' },
    },
    {
      name: 'parent',
      type: 'relationship',
      relationTo: 'categories',
      admin: { position: 'sidebar' },
      filterOptions: ({ id }) => (id ? { id: { not_equals: id } } : true),
    },
    {
      name: 'showInMenu',
      type: 'checkbox',
      defaultValue: false,
      admin: { position: 'sidebar', description: 'Hint for the website navigation.' },
    },
    wpId(),
  ],
  hooks: {
    afterChange: [
      async ({ doc, req }) => {
        await notifyFrontend(req, {
          collection: 'categories',
          event: 'change',
          id: doc.id,
          slug: doc.slug,
          paths: [paths.category(doc.slug)].filter(Boolean) as string[],
          tags: ['categories', `category:${doc.slug}`],
        })
        return doc
      },
    ],
  },
}
