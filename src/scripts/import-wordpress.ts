/**
 * WordPress -> Payload importer. READ-ONLY on the WordPress side.
 *
 * It only sends GET requests to the WordPress REST API and downloads image files.
 * It never creates, edits or deletes anything on WordPress, so the live site is untouched.
 * Re-running is safe: records are matched by their WordPress ID and updated, not duplicated.
 *
 * Usage:
 *   pnpm import:wp                         # everything
 *   pnpm import:wp --limit=100             # test run: newest 100 posts (+ taxonomies, authors)
 *   pnpm import:wp --only=posts --since=2026-10-01
 *   pnpm import:wp --only=pages
 *   pnpm import:wp --skip-media            # don't download images (faster test)
 *
 * Options can also be given as environment variables: IMPORT_LIMIT, IMPORT_ONLY, IMPORT_SINCE,
 * IMPORT_SKIP_MEDIA=true.
 */
import { convertHTMLToLexical, editorConfigFactory } from '@payloadcms/richtext-lexical'
import { JSDOM } from 'jsdom'
import { getPayload } from 'payload'
import type { Payload } from 'payload'

import config from '../payload.config'
import { htmlToText } from '../utilities/text'

// ---------- CLI ----------
const arg = (name: string) => {
  const hit = process.argv.find((a) => a === `--${name}` || a.startsWith(`--${name}=`))
  if (hit) return hit.includes('=') ? hit.split('=').slice(1).join('=') : 'true'
  const env = process.env[`IMPORT_${name.toUpperCase().replace(/-/g, '_')}`]
  return env || undefined
}
const LIMIT = arg('limit') ? Number(arg('limit')) : Infinity
const ONLY = arg('only') // posts | pages | taxonomies | authors
const SINCE = arg('since')
const SKIP_MEDIA = arg('skip-media') === 'true'

const WP = (process.env.WP_BASE_URL || 'https://canadiansme.ca').replace(/\/$/, '')
const AUTH =
  process.env.WP_USERNAME && process.env.WP_APP_PASSWORD
    ? 'Basic ' +
      Buffer.from(`${process.env.WP_USERNAME}:${process.env.WP_APP_PASSWORD.replace(/\s+/g, '')}`).toString(
        'base64',
      )
    : null

const CTX = { disableRevalidate: true, preserveSlug: true, fromImport: true }

// ---------- WordPress (GET only) ----------
type WpList<T> = { items: T[]; total: number; totalPages: number }

const wpGet = async <T = any>(route: string, params: Record<string, string | number> = {}): Promise<WpList<T>> => {
  const url = new URL(`${WP}/wp-json${route}`)
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, String(v)))
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const res = await fetch(url, {
        method: 'GET', // the importer never sends anything but GET to WordPress
        headers: { Accept: 'application/json', ...(AUTH ? { Authorization: AUTH } : {}) },
      })
      if (res.status === 400 && params.page) return { items: [], total: 0, totalPages: 0 } // past last page
      if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`)
      const data = await res.json()
      return {
        items: Array.isArray(data) ? data : [data],
        total: Number(res.headers.get('x-wp-total') || 0),
        totalPages: Number(res.headers.get('x-wp-totalpages') || 1),
      }
    } catch (err) {
      if (attempt === 4) throw err
      await new Promise((r) => setTimeout(r, 1500 * attempt))
    }
  }
  throw new Error('unreachable')
}

async function* wpPaged<T = any>(route: string, params: Record<string, string | number> = {}, perPage = 100) {
  let page = 1
  let totalPages = 1
  do {
    const res = await wpGet<T>(route, { ...params, per_page: perPage, page })
    totalPages = res.totalPages
    for (const item of res.items) yield item
    page++
  } while (page <= totalPages)
}

// ---------- helpers ----------
const decode = (s: unknown) => htmlToText(s)

const findByWpId = async (payload: Payload, collection: any, id: number) => {
  const res = await payload.find({
    collection,
    where: { wpId: { equals: id } },
    limit: 1,
    depth: 0,
    draft: true,
    overrideAccess: true,
    pagination: false,
  })
  return (res.docs[0] as any) ?? null
}

const upsert = async (payload: Payload, collection: any, wpIdValue: number, data: any, draftable = false) => {
  let existing = await findByWpId(payload, collection, wpIdValue)
  // Adopt a record someone already created by hand with the same URL slug (no duplicate URLs).
  if (!existing && data.slug) {
    const bySlug = await payload.find({
      collection,
      where: { and: [{ slug: { equals: data.slug } }, { wpId: { exists: false } }] },
      limit: 1,
      depth: 0,
      draft: true,
      overrideAccess: true,
      pagination: false,
    })
    existing = (bySlug.docs[0] as any) ?? null
  }
  const common = { collection, data: { ...data, wpId: wpIdValue }, overrideAccess: true, context: CTX, depth: 0 }
  const opts = draftable ? { ...common, draft: data._status !== 'published' } : common
  if (existing) return payload.update({ ...(opts as any), id: existing.id })
  return payload.create(opts as any)
}

const counts: Record<string, number> = {}
const bump = (k: string) => (counts[k] = (counts[k] || 0) + 1)

// ---------- taxonomies ----------
const categoryMap = new Map<number, any>()
const tagMap = new Map<number, any>()
const authorMap = new Map<number, any>()
const mediaMap = new Map<number, any>()

async function importCategories(payload: Payload) {
  const all: any[] = []
  for await (const c of wpPaged('/wp/v2/categories')) all.push(c)
  for (const c of all) {
    try {
      const doc: any = await upsert(payload, 'categories', c.id, {
        title: decode(c.name),
        slug: c.slug,
        description: decode(c.description) || null,
      })
      categoryMap.set(c.id, doc.id)
      bump('categories')
    } catch (err) {
      bump('categoryErrors')
      console.error(`  category ${c.id} (${c.slug}) failed: ${(err as Error).message}`)
    }
  }
  // Second pass: parents (needs every category to exist first).
  for (const c of all.filter((c) => c.parent)) {
    const parentId = categoryMap.get(c.parent)
    if (parentId && categoryMap.get(c.id)) {
      await payload.update({
        collection: 'categories',
        id: categoryMap.get(c.id)!,
        data: { parent: parentId },
        overrideAccess: true,
        context: CTX,
      })
    }
  }
  console.log(`  categories: ${all.length}`)
}

async function importTags(payload: Payload) {
  let n = 0
  for await (const t of wpPaged('/wp/v2/tags')) {
    try {
      const doc: any = await upsert(payload, 'tags', t.id, {
        title: decode(t.name),
        slug: t.slug,
        description: decode(t.description) || null,
      })
      tagMap.set(t.id, doc.id)
      n++
    } catch (err) {
      bump('tagErrors')
      console.error(`  tag ${t.id} (${t.slug}) failed: ${(err as Error).message}`)
    }
  }
  console.log(`  tags: ${n}`)
}

async function importAuthor(payload: Payload, u: any) {
  const avatarUrl: string | undefined = u.avatar_urls?.['96']
  const doc: any = await upsert(payload, 'authors', u.id, {
    name: decode(u.name) || u.slug,
    slug: u.slug,
    bio: decode(u.description) || null,
    links: { website: u.url || null },
  })
  authorMap.set(u.id, doc.id)
  // Keep the WordPress avatar URL as a hint if it's a site upload; skip gravatar.
  if (avatarUrl && !SKIP_MEDIA && avatarUrl.includes('/wp-content/uploads/') && !doc.avatar) {
    const media = await importMediaFromUrl(payload, avatarUrl.replace(/-\d+x\d+(\.\w+)$/, '$1'), decode(u.name))
    if (media) {
      await payload.update({ collection: 'authors', id: doc.id, data: { avatar: media }, overrideAccess: true, context: CTX })
    }
  }
  bump('authors')
  return doc.id
}

async function importAuthors(payload: Payload) {
  let n = 0
  try {
    for await (const u of wpPaged('/wp/v2/users')) {
      try {
        await importAuthor(payload, u)
        n++
      } catch (err) {
        console.error(`  author ${u.id} (${u.slug}) failed: ${(err as Error).message}`)
      }
    }
  } catch (err) {
    console.warn(`  could not list users (${(err as Error).message}); authors will be imported per post`)
  }
  console.log(`  authors: ${n}`)
}

const ensureAuthor = async (payload: Payload, wpUserId: number) => {
  if (authorMap.has(wpUserId)) return authorMap.get(wpUserId)!
  const existing = await findByWpId(payload, 'authors', wpUserId)
  if (existing) {
    authorMap.set(wpUserId, existing.id)
    return existing.id
  }
  try {
    const { items } = await wpGet(`/wp/v2/users/${wpUserId}`)
    return await importAuthor(payload, items[0])
  } catch {
    return null
  }
}

// ---------- media ----------
const guessMime = (url: string) => {
  const ext = url.split('?')[0].split('.').pop()?.toLowerCase()
  return (
    { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml', avif: 'image/avif', pdf: 'application/pdf' } as Record<string, string>
  )[ext || ''] || 'application/octet-stream'
}

async function importMediaFromUrl(payload: Payload, url: string, alt?: string, extra: any = {}) {
  const existing = await payload.find({
    collection: 'media',
    where: { wpUrl: { equals: url } },
    limit: 1,
    depth: 0,
    overrideAccess: true,
  })
  if (existing.docs[0]) return existing.docs[0].id
  const res = await fetch(url, { method: 'GET' })
  if (!res.ok) {
    console.warn(`    image ${res.status}: ${url}`)
    return null
  }
  const buf = Buffer.from(await res.arrayBuffer())
  const name = decodeURIComponent(url.split('?')[0].split('/').pop() || 'image')
  const doc: any = await payload.create({
    collection: 'media',
    data: { alt: alt || '', wpUrl: url, ...extra },
    file: { data: buf, mimetype: res.headers.get('content-type') || guessMime(url), name, size: buf.length },
    overrideAccess: true,
    context: CTX,
  })
  bump('media')
  return doc.id
}

async function importMedia(payload: Payload, wpMediaId: number) {
  if (!wpMediaId || SKIP_MEDIA) return null
  if (mediaMap.has(wpMediaId)) return mediaMap.get(wpMediaId)!
  const existing = await findByWpId(payload, 'media', wpMediaId)
  if (existing) {
    mediaMap.set(wpMediaId, existing.id)
    return existing.id
  }
  try {
    const { items } = await wpGet(`/wp/v2/media/${wpMediaId}`)
    const m = items[0]
    const caption = decode(m.caption?.rendered)
    const id = await importMediaFromUrl(payload, m.source_url, m.alt_text || decode(m.title?.rendered), {
      wpId: m.id,
      caption: caption || null,
      credit: /courtesy|credit/i.test(caption) ? caption : null,
    })
    mediaMap.set(wpMediaId, id)
    return id
  } catch (err) {
    console.warn(`    media ${wpMediaId} skipped: ${(err as Error).message}`)
    mediaMap.set(wpMediaId, null)
    return null
  }
}

// ---------- content ----------
let editorConfig: any = null
const getEditorConfig = (payload: Payload, collection: 'posts' | 'pages') => {
  if (editorConfig) return editorConfig
  const field = (payload.collections[collection].config.flattenedFields as any[]).find((f) => f.name === 'content')
  editorConfig = editorConfigFactory.fromField({ field })
  return editorConfig
}

/** Things the rich-text conversion can't represent 1:1 -> keep showing the original HTML. */
const NEEDS_LEGACY = /<(img|iframe|figure|table|video|audio|embed|object|script|form|svg)\b|class="[^"]*(twitter-tweet|instagram-media|wp-block-embed|elementor)/i

const toLexical = (payload: Payload, html: string, collection: 'posts' | 'pages') => {
  try {
    return convertHTMLToLexical({ editorConfig: getEditorConfig(payload, collection), html, JSDOM: JSDOM as any })
  } catch (err) {
    console.warn(`    HTML conversion failed, keeping original HTML only: ${(err as Error).message}`)
    return null
  }
}

const SUFFIX = /\s*[-|]\s*CanadianSME Small Business Magazine\s*$/i

const seoFrom = (wp: any, title: string, featuredImage: any, publicUrl: string) => {
  const h = wp.aioseo_head_json || wp.yoast_head_json || {}
  const metaTitle = typeof h.title === 'string' ? decode(h.title).replace(SUFFIX, '') : ''
  const canonical: string = h.canonical_url || h.canonical || ''
  const robots: string = typeof h.robots === 'string' ? h.robots : Object.values(h.robots || {}).join(',')
  return {
    title: metaTitle && metaTitle !== title ? metaTitle : null,
    description: typeof h.description === 'string' ? decode(h.description) : null,
    image: featuredImage || null,
    canonicalUrl: canonical && canonical.replace(/\/$/, '') !== publicUrl.replace(/\/$/, '') ? canonical : null,
    noIndex: /noindex/i.test(robots),
  }
}

const STATUS_PARAM = AUTH ? 'publish,draft,pending,private,future' : 'publish'

async function importPosts(payload: Payload) {
  const params: Record<string, string | number> = { orderby: 'date', order: 'desc', status: STATUS_PARAM, context: 'view' }
  if (SINCE) params.modified_after = new Date(SINCE).toISOString()
  let n = 0
  for await (const p of wpPaged('/wp/v2/posts', params, 50)) {
    if (n >= LIMIT) break
    n++
    try {
      const title = decode(p.title?.rendered) || '(untitled)'
      const html: string = p.content?.rendered || ''
      const featured = await importMedia(payload, p.featured_media)
      const authorId = p.author ? await ensureAuthor(payload, p.author) : null
      const content = toLexical(payload, html, 'posts')
      const published = p.status === 'publish'
      await upsert(
        payload,
        'posts',
        p.id,
        {
          title,
          slug: p.slug || undefined,
          generateSlug: false,
          excerpt: decode(p.excerpt?.rendered).replace(/\s*(\.\.\.|\[\.\.\.\])$/, '...') || null,
          featuredImage: featured,
          content,
          legacyHtml: html,
          useLegacyHtml: !content || NEEDS_LEGACY.test(html),
          authors: authorId ? [authorId] : [],
          categories: (p.categories || []).map((id: number) => categoryMap.get(id)).filter(Boolean),
          primaryCategory: categoryMap.get((p.categories || [])[0]) || null,
          tags: (p.tags || []).map((id: number) => tagMap.get(id)).filter(Boolean),
          isFeatured: Boolean(p.sticky),
          publishedAt: p.date_gmt ? `${p.date_gmt}Z` : null,
          meta: seoFrom(p, title, featured, p.link || `${WP}/${p.slug}/`),
          _status: published ? 'published' : 'draft',
        },
        true,
      )
      bump('posts')
      if (n % 25 === 0) console.log(`  posts: ${n}...`)
    } catch (err) {
      bump('postErrors')
      console.error(`  post ${p.id} (${p.slug}) failed: ${(err as Error).message}`)
    }
  }
  console.log(`  posts: ${n}`)
}

async function importPages(payload: Payload) {
  let n = 0
  for await (const p of wpPaged('/wp/v2/pages', { status: STATUS_PARAM }, 50)) {
    try {
      const title = decode(p.title?.rendered) || '(untitled)'
      const html: string = p.content?.rendered || ''
      const featured = await importMedia(payload, p.featured_media)
      const content = toLexical(payload, html, 'pages')
      await upsert(
        payload,
        'pages',
        p.id,
        {
          title,
          slug: p.slug || undefined,
          generateSlug: false,
          featuredImage: featured,
          content,
          legacyHtml: html,
          // Pages are usually built with Elementor/shortcodes: show the original HTML by default.
          useLegacyHtml: true,
          meta: seoFrom(p, title, featured, p.link || `${WP}/${p.slug}/`),
          _status: p.status === 'publish' ? 'published' : 'draft',
        },
        true,
      )
      n++
      bump('pages')
    } catch (err) {
      bump('pageErrors')
      console.error(`  page ${p.id} (${p.slug}) failed: ${(err as Error).message}`)
    }
  }
  console.log(`  pages: ${n}`)
}

// ---------- main ----------
const run = async () => {
  const started = Date.now()
  console.log(`Importing from ${WP} (read-only)${AUTH ? ' with app password (drafts included)' : ' (published only)'}`)
  const payload = await getPayload({ config })

  // Load existing mappings so partial runs (e.g. --only=posts) still link categories/tags.
  const preload = async (collection: any, map: Map<number, any>) => {
    const res = await payload.find({ collection, limit: 0, pagination: false, depth: 0, overrideAccess: true, select: { wpId: true } as any })
    for (const d of res.docs as any[]) if (d.wpId) map.set(d.wpId, d.id)
  }
  await preload('categories', categoryMap)
  await preload('tags', tagMap)
  await preload('authors', authorMap)

  if (!ONLY || ONLY === 'taxonomies') {
    console.log('Categories & tags')
    await importCategories(payload)
    await importTags(payload)
  }
  if (!ONLY || ONLY === 'authors') {
    console.log('Authors')
    await importAuthors(payload)
  }
  if (!ONLY || ONLY === 'posts') {
    console.log(`Posts${Number.isFinite(LIMIT) ? ` (limit ${LIMIT})` : ''}`)
    await importPosts(payload)
  }
  if (!ONLY || ONLY === 'pages') {
    console.log('Pages')
    await importPages(payload)
  }

  console.log(`\nDone in ${Math.round((Date.now() - started) / 1000)}s`, counts)
  process.exit(counts.postErrors || counts.pageErrors ? 1 : 0)
}

try {
  await run()
} catch (err) {
  console.error(err)
  process.exit(1)
}
