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
 *   pnpm import:wp --concurrency=8         # articles processed in parallel (default 6)
 *   pnpm import:wp --skip-existing         # resume: skip articles already imported
 *
 * Options can also be given as environment variables: IMPORT_LIMIT, IMPORT_ONLY, IMPORT_SINCE,
 * IMPORT_SKIP_MEDIA=true.
 */
import { convertHTMLToLexical, editorConfigFactory } from '@payloadcms/richtext-lexical'
import type { Payload } from 'payload'

import wpAuthors from '../data/wp-authors.json'
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

/** Saves; if only the converted body is rejected, saves again with the original HTML only. */
const upsertWithFallback = async (payload: Payload, collection: any, wpIdValue: number, data: any) => {
  try {
    return await upsert(payload, collection, wpIdValue, data, true)
  } catch (err: any) {
    const fields: string[] = (err?.data?.errors || []).map((e: any) => String(e.path || ''))
    const contentOnly = fields.length > 0 && fields.every((f) => f === 'content' || f.startsWith('content.'))
    if (!contentOnly && !/Content/.test(err?.message || '')) throw err
    bump('htmlFallbacks')
    return upsert(payload, collection, wpIdValue, { ...data, content: null, useLegacyHtml: true }, true)
  }
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

/**
 * Public byline list (WordPress ID, name, slug, website; no emails), exported once because
 * the site's user list isn't public. Used when the WordPress API won't list users.
 */
const knownAuthors = (): any[] => wpAuthors as any[]

async function importAuthors(payload: Payload) {
  let n = 0
  const listed = knownAuthors()
  if (listed.length) {
    for (const u of listed) {
      try {
        await importAuthor(payload, { ...u, description: '' })
        n++
      } catch (err) {
        console.error(`  author ${u.id} (${u.slug}) failed: ${(err as Error).message}`)
      }
    }
    console.log(`  authors: ${n} (from data/wp-authors.json)`)
    return
  }
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

const ensureAuthor = async (payload: Payload, wpUserId: number, embedded?: any) => {
  if (authorMap.has(wpUserId)) return authorMap.get(wpUserId)!
  // The public post data includes the author's name and slug, even when the user list is private.
  if (embedded && embedded.id === wpUserId && embedded.slug) {
    return await importAuthor(payload, embedded)
  }
  const known = knownAuthors().find((u) => u.id === wpUserId)
  if (known) return await importAuthor(payload, { ...known, description: '' })
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

/** Node types the article editor can store. Anything else is unwrapped or dropped. */
const KEEP = new Set([
  'root', 'paragraph', 'text', 'heading', 'list', 'listitem', 'quote', 'link', 'autolink',
  'linebreak', 'horizontalrule', 'tab',
])

const fixUrl = (raw: unknown): string | null => {
  if (typeof raw !== 'string') return null
  const url = raw.trim()
  if (!url || url.startsWith('#')) return null
  if (/^(mailto|tel):/i.test(url)) return url
  try {
    const u = new URL(url, `${WP}/`)
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : null
  } catch {
    return null
  }
}

/** Removes nodes the editor would reject (inline images, broken links, unknown blocks). */
const cleanNodes = (nodes: any[]): any[] => {
  const out: any[] = []
  for (const node of nodes || []) {
    if (!node || typeof node !== 'object') continue
    if (node.type === 'link' || node.type === 'autolink') {
      const url = fixUrl(node.fields?.url ?? node.url)
      const children = cleanNodes(node.children)
      if (!url) {
        out.push(...children) // keep the text, drop the broken link
        continue
      }
      out.push({ ...node, fields: { ...(node.fields || {}), url, linkType: 'custom' }, children })
      continue
    }
    if (node.type === 'heading' && !['h2', 'h3', 'h4', 'h5', 'h6'].includes(node.tag)) {
      node.tag = 'h2'
    }
    if (!KEEP.has(node.type)) {
      // Unknown or unsupported node: keep its text content if it has children.
      if (Array.isArray(node.children)) out.push(...cleanNodes(node.children))
      continue
    }
    if (Array.isArray(node.children)) node.children = cleanNodes(node.children)
    out.push(node)
  }
  return out
}

const BLOCK_TYPES = new Set(['paragraph', 'heading', 'list', 'quote', 'horizontalrule'])

const cleanLexical = (state: any) => {
  if (!state?.root) return null
  let children = cleanNodes(state.root.children)
  // The root may only contain block nodes; wrap stray inline nodes in paragraphs.
  const fixed: any[] = []
  let buffer: any[] = []
  const flush = () => {
    if (buffer.length) {
      fixed.push({ type: 'paragraph', version: 1, direction: null, format: '', indent: 0, textFormat: 0, children: buffer })
      buffer = []
    }
  }
  for (const n of children) {
    if (BLOCK_TYPES.has(n.type)) {
      flush()
      fixed.push(n)
    } else buffer.push(n)
  }
  flush()
  children = fixed
  if (!children.length) return null
  return { ...state, root: { ...state.root, children } }
}

/**
 * Converting HTML into the rich-text editor needs jsdom, which only runs in the command-line
 * importer (Node 24). The in-CMS importer turns conversion off and keeps the original HTML,
 * which the website shows exactly as WordPress did.
 */
let convertEnabled = true
export const setConvertHtml = (on: boolean) => {
  convertEnabled = on
}
let jsdomCtor: any = null

const toLexical = async (payload: Payload, html: string, collection: 'posts' | 'pages') => {
  if (!convertEnabled) return null
  try {
    if (!jsdomCtor) jsdomCtor = (await import('jsdom')).JSDOM
    return cleanLexical(
      convertHTMLToLexical({ editorConfig: getEditorConfig(payload, collection), html, JSDOM: jsdomCtor }),
    )
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

const CONCURRENCY = Math.max(1, Math.min(12, Number(arg('concurrency') || 6)))
const SKIP_EXISTING = arg('skip-existing') === 'true'

/** Runs `fn` over `items` with at most `limit` running at the same time. */
const pool = async <T>(items: T[], limit: number, fn: (item: T) => Promise<void>) => {
  let i = 0
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const item = items[i++]
      await fn(item)
    }
  })
  await Promise.all(workers)
}

async function importOnePost(payload: Payload, p: any) {
  try {
    const title = decode(p.title?.rendered) || '(untitled)'
    const html: string = p.content?.rendered || ''
    const featured = await importMedia(payload, p.featured_media)
    const authorId = p.author ? await ensureAuthor(payload, p.author, p._embedded?.author?.[0]) : null
    const content = await toLexical(payload, html, 'posts')
    const published = p.status === 'publish'
    await upsertWithFallback(payload, 'posts', p.id, {
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
    })
    bump('posts')
  } catch (err) {
    bump('postErrors')
    console.error(`  post ${p.id} (${p.slug}) failed: ${(err as Error).message}`)
  }
}

async function importPosts(payload: Payload) {
  const params: Record<string, string | number> = {
    orderby: 'date',
    order: 'desc',
    status: STATUS_PARAM,
    context: 'view',
    _embed: 'author',
  }
  if (SINCE) params.modified_after = new Date(SINCE).toISOString()

  // With --skip-existing, articles already imported are skipped, so an interrupted run resumes quickly.
  const existing = new Set<number>()
  if (SKIP_EXISTING) {
    const res = await payload.find({
      collection: 'posts',
      limit: 0,
      pagination: false,
      depth: 0,
      draft: true,
      overrideAccess: true,
      select: { wpId: true } as any,
    })
    for (const d of res.docs as any[]) if (d.wpId) existing.add(d.wpId)
    console.log(`  ${existing.size} articles already imported will be skipped`)
  }

  const started = Date.now()
  let seen = 0
  let batch: any[] = []
  const flush = async () => {
    const todo = batch.filter((p) => !existing.has(p.id))
    if (batch.length > todo.length) counts.skipped = (counts.skipped || 0) + batch.length - todo.length
    batch = []
    await pool(todo, CONCURRENCY, (p) => importOnePost(payload, p))
    const mins = (Date.now() - started) / 60000
    console.log(`  posts: ${seen} read, ${counts.posts || 0} saved, ${counts.postErrors || 0} errors (${mins.toFixed(1)} min)`)
  }
  for await (const p of wpPaged('/wp/v2/posts', params, 50)) {
    if (seen >= LIMIT) break
    seen++
    batch.push(p)
    if (batch.length >= 50) await flush()
  }
  if (batch.length) await flush()
  console.log(`  posts: ${seen}`)
}

async function importPages(payload: Payload) {
  let n = 0
  for await (const p of wpPaged('/wp/v2/pages', { status: STATUS_PARAM }, 50)) {
    if (await importOnePage(payload, p)) n++
  }
  console.log(`  pages: ${n}`)
}

async function importOnePage(payload: Payload, p: any): Promise<boolean> {
    try {
      const title = decode(p.title?.rendered) || '(untitled)'
      const html: string = p.content?.rendered || ''
      const featured = await importMedia(payload, p.featured_media)
      const content = await toLexical(payload, html, 'pages')
      await upsertWithFallback(
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
      )
      bump('pages')
      return true
    } catch (err) {
      bump('pageErrors')
      console.error(`  page ${p.id} (${p.slug}) failed: ${(err as Error).message}`)
      return false
    }
}

// ---------- shared entry points ----------
export const resetCounts = () => {
  for (const k of Object.keys(counts)) delete counts[k]
}

/** Loads existing WordPress-ID mappings so partial runs still link categories, tags and authors. */
export const preloadMaps = async (payload: Payload) => {
  const preload = async (collection: any, map: Map<number, any>) => {
    const res = await payload.find({ collection, limit: 0, pagination: false, depth: 0, overrideAccess: true, select: { wpId: true } as any })
    for (const d of res.docs as any[]) if (d.wpId) map.set(d.wpId, d.id)
  }
  await preload('categories', categoryMap)
  await preload('tags', tagMap)
  await preload('authors', authorMap)
}

/** Imports one page of WordPress articles (newest first). Used by the in-CMS importer. */
export const importPostsPage = async (payload: Payload, page: number, perPage = 20, concurrency = 6) => {
  const res = await wpGet('/wp/v2/posts', {
    orderby: 'date',
    order: 'desc',
    status: STATUS_PARAM,
    _embed: 'author',
    per_page: perPage,
    page,
  })
  await pool(res.items, concurrency, (p) => importOnePost(payload, p))
  return { totalPages: res.totalPages, total: res.total, read: res.items.length }
}

/** Imports one page of WordPress pages. */
export const importPagesPage = async (payload: Payload, page: number, perPage = 20) => {
  const res = await wpGet('/wp/v2/pages', { status: STATUS_PARAM, per_page: perPage, page })
  for (const p of res.items) await importOnePage(payload, p)
  return { totalPages: res.totalPages, total: res.total, read: res.items.length }
}

export const runCli = async (payload: Payload) => {
  const started = Date.now()
  console.log(`Importing from ${WP} (read-only)${AUTH ? ' with app password (drafts included)' : ' (published only)'}`)
  await preloadMaps(payload)
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
  return counts
}

export { counts, importAuthors, importCategories, importTags }
