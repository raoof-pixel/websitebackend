import type {
  CollectionAfterChangeHook,
  CollectionAfterDeleteHook,
  CollectionBeforeChangeHook,
  CollectionConfig,
} from 'payload'

import { canCreateContent, canEditOwnOrAll, publishedOrAuthenticated } from '../access'
import { legacyHtmlFields } from '../fields/legacyHtml'
import { articleEditor } from '../fields/richText'
import { slug } from '../fields/slug'
import { wpId } from '../fields/wordpress'
import { getSiteURL, notifyFrontend, paths } from '../utilities/revalidate'
import { htmlToText, lexicalToText, readingMinutes } from '../utilities/text'

const idOf = (v: unknown) => (v && typeof v === 'object' ? (v as { id: unknown }).id : v)

/** Fills in defaults and derived values before every save. */
const prepare: CollectionBeforeChangeHook = async ({ data, operation, originalDoc, req }) => {
  const user = req.user as { id: number | string; author?: unknown } | null

  if (operation === 'create') {
    if (user && !data.createdBy) data.createdBy = user.id
    // New articles get the logged-in person's byline by default.
    if ((!data.authors || data.authors.length === 0) && user?.author) {
      data.authors = [idOf(user.author)]
    }
  }

  // Set the publish date the first time an article goes live.
  if (data._status === 'published' && !data.publishedAt) {
    data.publishedAt = new Date().toISOString()
  }

  // Primary category defaults to the first selected category.
  if (!data.primaryCategory && Array.isArray(data.categories) && data.categories.length > 0) {
    data.primaryCategory = idOf(data.categories[0])
  }

  // Once an editor edits an imported article in the rich-text editor, use that content.
  if (
    operation === 'update' &&
    !req.context?.fromImport &&
    originalDoc?.useLegacyHtml &&
    data.content !== undefined &&
    JSON.stringify(data.content) !== JSON.stringify(originalDoc.content)
  ) {
    data.useLegacyHtml = false
  }

  const useLegacy = data.useLegacyHtml ?? originalDoc?.useLegacyHtml
  const text = useLegacy
    ? htmlToText(data.legacyHtml ?? originalDoc?.legacyHtml)
    : lexicalToText(data.content ?? originalDoc?.content)
  if (text) data.readingTime = readingMinutes(text)

  return data
}

const revalidateAfterChange: CollectionAfterChangeHook = async ({ doc, previousDoc, req }) => {
  const wasPublished = previousDoc?._status === 'published'
  const isPublished = doc._status === 'published'
  if (!wasPublished && !isPublished) return doc // draft-only edits don't affect the website

  const pathList = new Set<string>()
  if (isPublished) pathList.add(paths.post(doc.slug)!)
  if (wasPublished && previousDoc?.slug !== doc.slug) pathList.add(paths.post(previousDoc.slug)!)
  if (wasPublished && !isPublished) pathList.add(paths.post(previousDoc.slug)!)
  pathList.add('/')

  await notifyFrontend(req, {
    collection: 'posts',
    event: 'change',
    id: doc.id,
    slug: doc.slug,
    paths: [...pathList].filter(Boolean),
    tags: ['posts', `post:${doc.slug}`],
  })
  return doc
}

const revalidateAfterDelete: CollectionAfterDeleteHook = async ({ doc, req }) => {
  await notifyFrontend(req, {
    collection: 'posts',
    event: 'delete',
    id: doc.id,
    slug: doc.slug,
    paths: [paths.post(doc.slug), '/'].filter(Boolean) as string[],
    tags: ['posts', `post:${doc.slug}`],
  })
  return doc
}

/**
 * Articles. Public URL: https://canadiansme.ca/<slug>/ (same as WordPress today).
 */
export const Posts: CollectionConfig = {
  slug: 'posts',
  labels: { singular: 'Article', plural: 'Articles' },
  admin: {
    useAsTitle: 'title',
    defaultColumns: ['title', 'primaryCategory', 'authors', '_status', 'publishedAt'],
    listSearchableFields: ['title', 'slug', 'excerpt'],
    group: 'Content',
    pagination: { defaultLimit: 25 },
    preview: (doc) => {
      const secret = process.env.PREVIEW_SECRET
      const slugValue = typeof doc?.slug === 'string' ? doc.slug : ''
      if (!secret || !slugValue) return null
      const params = new URLSearchParams({ secret, path: `/${slugValue}/`, collection: 'posts' })
      return `${getSiteURL()}/api/preview?${params.toString()}`
    },
  },
  // What a post looks like when it's referenced from another document (e.g. related posts).
  defaultPopulate: {
    title: true,
    slug: true,
    excerpt: true,
    featuredImage: true,
    publishedAt: true,
    primaryCategory: true,
  },
  access: {
    read: publishedOrAuthenticated,
    create: canCreateContent,
    update: canEditOwnOrAll,
    delete: canEditOwnOrAll,
    readVersions: ({ req }) => Boolean(req.user),
  },
  fields: [
    { name: 'title', type: 'text', required: true },
    {
      name: 'excerpt',
      type: 'textarea',
      admin: { description: 'Short summary shown on listing pages and in social shares.' },
    },
    {
      name: 'featuredImage',
      type: 'upload',
      relationTo: 'media',
    },
    {
      name: 'content',
      type: 'richText',
      editor: articleEditor,
    },
    ...legacyHtmlFields(),

    // ----- Sidebar -----
    slug(),
    {
      name: 'publishedAt',
      type: 'date',
      index: true,
      admin: {
        position: 'sidebar',
        date: { pickerAppearance: 'dayAndTime' },
        description: 'Set automatically when first published. To schedule, use "Schedule Publish".',
      },
    },
    {
      name: 'authors',
      type: 'relationship',
      relationTo: 'authors',
      hasMany: true,
      admin: { position: 'sidebar' },
    },
    {
      name: 'categories',
      type: 'relationship',
      relationTo: 'categories',
      hasMany: true,
      index: true,
      admin: { position: 'sidebar' },
    },
    {
      name: 'primaryCategory',
      type: 'relationship',
      relationTo: 'categories',
      index: true,
      admin: {
        position: 'sidebar',
        description: 'Used for the breadcrumb and the label on cards. Defaults to the first category.',
      },
      filterOptions: ({ data }) => {
        const ids = Array.isArray(data?.categories) ? data.categories.map(idOf).filter(Boolean) : []
        return ids.length ? { id: { in: ids } } : true
      },
    },
    {
      name: 'tags',
      type: 'relationship',
      relationTo: 'tags',
      hasMany: true,
      index: true,
      admin: { position: 'sidebar' },
    },
    {
      type: 'row',
      admin: { position: 'sidebar' },
      fields: [
        { name: 'isFeatured', type: 'checkbox', label: 'Featured', index: true },
        { name: 'isEditorsPick', type: 'checkbox', label: "Editor's pick", index: true },
        { name: 'isSponsored', type: 'checkbox', label: 'Sponsored' },
      ],
    },
    {
      name: 'sourceUrl',
      type: 'text',
      admin: {
        position: 'sidebar',
        description: 'Original press release (e.g. a newswire.ca link), if any.',
      },
    },
    {
      name: 'relatedPosts',
      type: 'relationship',
      relationTo: 'posts',
      hasMany: true,
      admin: { position: 'sidebar' },
      filterOptions: ({ id }) => (id ? { id: { not_equals: id } } : true),
    },
    {
      name: 'readingTime',
      type: 'number',
      admin: { position: 'sidebar', readOnly: true, description: 'Minutes (calculated).' },
    },
    {
      name: 'createdBy',
      type: 'relationship',
      relationTo: 'users',
      admin: { position: 'sidebar', readOnly: true },
    },
    wpId(),
  ],
  hooks: {
    beforeChange: [prepare],
    afterChange: [revalidateAfterChange],
    afterDelete: [revalidateAfterDelete],
  },
  versions: {
    drafts: {
      autosave: { interval: 2000 },
      schedulePublish: true,
    },
    maxPerDoc: 25,
  },
}
