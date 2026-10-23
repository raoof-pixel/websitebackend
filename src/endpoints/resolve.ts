import type { Endpoint, PayloadRequest, Where } from 'payload'

/**
 * GET /api/resolve?path=/some-article-slug/
 *
 * One call that tells the website what lives at a URL, so a single catch-all route can
 * render everything with the same URLs WordPress used:
 *
 *   /<slug>/            -> post (or page)
 *   /category/<slug>/   -> category
 *   /tag/<slug>/        -> tag
 *   /author/<slug>/     -> author
 *   anything else       -> checks the Redirects collection, then 404
 *
 * Response: { type, doc } | { type: 'redirect', to, status } | { type: 'notFound' } (404)
 * Add ?draft=true with a logged-in user or API key to see unpublished drafts (for previews).
 */
const normalise = (raw: string) => {
  let p = raw.trim()
  try {
    p = new URL(p, 'https://x.invalid').pathname
  } catch {
    // keep as-is
  }
  p = p.replace(/\/{2,}/g, '/')
  if (!p.startsWith('/')) p = `/${p}`
  return p
}

const findOne = async (
  req: PayloadRequest,
  collection: 'posts' | 'pages' | 'categories' | 'tags' | 'authors',
  where: Where,
  draft: boolean,
  depth: number,
) => {
  const res = await req.payload.find({
    collection,
    where,
    limit: 1,
    depth,
    draft,
    req,
    overrideAccess: false,
  })
  return res.docs[0] ?? null
}

const resolveRedirect = async (req: PayloadRequest, path: string) => {
  const variants = Array.from(
    new Set([path, path.replace(/\/$/, ''), path.endsWith('/') ? path : `${path}/`]),
  ).filter(Boolean)
  const res = await req.payload.find({
    collection: 'redirects',
    where: { from: { in: variants } },
    limit: 1,
    depth: 1,
    req,
    overrideAccess: true,
  })
  const r: any = res.docs[0]
  if (!r) return null
  let to: string | null = null
  if (r.to?.type === 'custom') to = r.to.url
  else if (r.to?.reference?.value) {
    const ref = r.to.reference
    const s = typeof ref.value === 'object' ? ref.value.slug : null
    if (s) to = `/${s}/`
  }
  if (!to) return null
  return { type: 'redirect' as const, to, status: Number(r.type) || 301 }
}

export const resolveEndpoint: Endpoint = {
  path: '/resolve',
  method: 'get',
  handler: async (req) => {
    const url = new URL(req.url || '', 'http://localhost')
    const rawPath = url.searchParams.get('path')
    if (!rawPath) {
      return Response.json({ error: 'Missing ?path=' }, { status: 400 })
    }
    const draft = url.searchParams.get('draft') === 'true' && Boolean(req.user)
    const depth = Math.min(Number(url.searchParams.get('depth') ?? 2) || 2, 3)
    const path = normalise(rawPath)
    const segments = path.split('/').filter(Boolean).map((s) => decodeURIComponent(s))

    const headers = { 'Cache-Control': draft ? 'no-store' : 's-maxage=60, stale-while-revalidate=600' }

    if (segments.length === 2 && ['category', 'tag', 'author'].includes(segments[0])) {
      const [kind, slugValue] = segments
      const collection = kind === 'category' ? 'categories' : kind === 'tag' ? 'tags' : 'authors'
      const doc = await findOne(req, collection, { slug: { equals: slugValue } }, false, 1)
      if (doc) return Response.json({ type: kind, doc }, { headers })
    }

    if (segments.length >= 1) {
      const last = segments[segments.length - 1]
      if (segments.length === 1) {
        const post = await findOne(req, 'posts', { slug: { equals: last } }, draft, depth)
        if (post) return Response.json({ type: 'post', doc: post }, { headers })
      }
      const page = await findOne(req, 'pages', { slug: { equals: last } }, draft, depth)
      if (page) return Response.json({ type: 'page', doc: page }, { headers })
    }

    const redirect = await resolveRedirect(req, path)
    if (redirect) return Response.json(redirect, { headers })

    return Response.json({ type: 'notFound' }, { status: 404, headers })
  },
}

/** GET /api/health — quick check that the server and database are reachable. */
export const healthEndpoint: Endpoint = {
  path: '/health',
  method: 'get',
  handler: async (req) => {
    try {
      await req.payload.count({ collection: 'categories', overrideAccess: true })
      return Response.json({ ok: true })
    } catch (err) {
      return Response.json({ ok: false, error: (err as Error).message }, { status: 500 })
    }
  },
}
