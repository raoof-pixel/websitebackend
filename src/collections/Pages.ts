import type { CollectionAfterChangeHook, CollectionConfig } from 'payload'

import { isStaff, publishedOrAuthenticated } from '../access'
import { legacyHtmlFields } from '../fields/legacyHtml'
import { articleEditor } from '../fields/richText'
import { slug } from '../fields/slug'
import { wpId } from '../fields/wordpress'
import { getSiteURL, notifyFrontend, paths } from '../utilities/revalidate'

const revalidatePage: CollectionAfterChangeHook = async ({ doc, previousDoc, req }) => {
  if (doc._status !== 'published' && previousDoc?._status !== 'published') return doc
  const list = new Set<string>([paths.page(doc.slug)!])
  if (previousDoc?.slug && previousDoc.slug !== doc.slug) list.add(paths.page(previousDoc.slug)!)
  await notifyFrontend(req, {
    collection: 'pages',
    event: 'change',
    id: doc.id,
    slug: doc.slug,
    paths: [...list].filter(Boolean),
    tags: ['pages', `page:${doc.slug}`],
  })
  return doc
}

/**
 * Standalone pages: About, Advertise, Contact, Subscription, etc. URL: /<slug>/
 * The website's own designed pages (home, category listings) don't need to live here.
 */
export const Pages: CollectionConfig = {
  slug: 'pages',
  admin: {
    useAsTitle: 'title',
    defaultColumns: ['title', 'slug', '_status', 'updatedAt'],
    group: 'Content',
    preview: (doc) => {
      const secret = process.env.PREVIEW_SECRET
      const slugValue = typeof doc?.slug === 'string' ? doc.slug : ''
      if (!secret || !slugValue) return null
      const params = new URLSearchParams({ secret, path: `/${slugValue}/`, collection: 'pages' })
      return `${getSiteURL()}/api/preview?${params.toString()}`
    },
  },
  access: {
    read: publishedOrAuthenticated,
    create: isStaff,
    update: isStaff,
    delete: isStaff,
    readVersions: ({ req }) => Boolean(req.user),
  },
  fields: [
    { name: 'title', type: 'text', required: true },
    { name: 'featuredImage', type: 'upload', relationTo: 'media' },
    { name: 'content', type: 'richText', editor: articleEditor },
    ...legacyHtmlFields(),
    slug(),
    {
      name: 'parent',
      type: 'relationship',
      relationTo: 'pages',
      admin: { position: 'sidebar' },
      filterOptions: ({ id }) => (id ? { id: { not_equals: id } } : true),
    },
    wpId(),
  ],
  hooks: {
    afterChange: [revalidatePage],
  },
  versions: {
    drafts: { autosave: { interval: 2000 } },
    maxPerDoc: 25,
  },
}
