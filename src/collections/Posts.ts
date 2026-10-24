import type {
  CollectionAfterChangeHook,
  CollectionAfterDeleteHook,
  CollectionBeforeChangeHook,
  CollectionConfig,
} from 'payload'
import { APIError } from 'payload'

import {
  authenticatedField,
  canCreateContent,
  canDeleteOwnOrAll,
  canUpdateOwnOrAll,
  isAutomationOnly,
  publishedOrAuthenticated,
} from '../access'
import { auditAfterChange, auditAfterDelete } from './AuditLogs'
import { legacyHtmlFields } from '../fields/legacyHtml'
import { articleEditor } from '../fields/richText'
import { slug } from '../fields/slug'
import { wpId } from '../fields/wordpress'
import { getWebsiteURL, notifyFrontend, paths } from '../utilities/revalidate'
import { htmlToText, lexicalToText, readingMinutes } from '../utilities/text'

const idOf = (v: unknown) => (v && typeof v === 'object' ? (v as { id: unknown }).id : v)

/** Fills in defaults and derived values before every save. */
const prepare: CollectionBeforeChangeHook = async ({ data, operation, originalDoc, req }) => {
  const user = req.user as { id: number | string; author?: unknown } | null

  // Bots can only save drafts for a person to review, unless explicitly allowed.
  if (isAutomationOnly(user as never) && process.env.AUTOMATION_CAN_PUBLISH !== 'true') {
    // ...and can't edit (and so silently unpublish) an article that is already live.
    if (operation === 'update' && originalDoc?._status === 'published') {
      throw new APIError('Automation accounts cannot change published articles.', 403, undefined, true)
    }
    data._status = 'draft'
  }

  if (operation === 'create') {
    if (user) data.createdBy = user.id
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
  // Autosaves and "Save draft" on a published article only change the draft, not the live page.
  const q = (req.query || {}) as Record<string, unknown>
  if (!isPublished && (q.autosave === 'true' || q.draft === 'true')) return doc

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
    // "Preview" button: the latest draft in the real website design (see endpoints/sitePreview).
    preview: (doc) => (doc?.id ? `/api/site-preview?collection=posts&id=${doc.id}` : null),
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
    update: canUpdateOwnOrAll,
    delete: canDeleteOwnOrAll,
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
      name: 'viewOnWebsite',
      type: 'ui',
      admin: {
        position: 'sidebar',
        components: {
          Field: { path: '/components/ViewOnSite#ViewOnSite', clientProps: { siteURL: getWebsiteURL() } },
        },
      },
    },
    {
      name: 'sourceUrl',
      type: 'text',
      validate: (v: unknown) =>
        !v || (typeof v === 'string' && /^https?:\/\//i.test(v)) ? true : 'Must start with http:// or https://',
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
      // Hidden from the public API and can't be changed after creation.
      access: { read: authenticatedField, update: () => false },
    },
    wpId(),
  ],
  hooks: {
    beforeChange: [prepare],
    afterChange: [revalidateAfterChange, auditAfterChange],
    afterDelete: [revalidateAfterDelete, auditAfterDelete],
  },
  versions: {
    drafts: {
      autosave: { interval: 2000 },
      schedulePublish: true,
    },
    maxPerDoc: 25,
  },
}
