import type { Endpoint } from 'payload'

import { hasRole } from '../access'
import { lexicalToHtml } from '../utilities/lexicalToHtml'
import { getWebsiteURL } from '../utilities/revalidate'
import { sanitizeHtml } from '../utilities/sanitizeHtml'

/**
 * GET /api/site-preview?collection=posts&id=123   (logged-in staff only)
 *
 * Shows the latest draft of an article in the real website design, before it is published.
 * The website publishes an article page with placeholders at /_preview/; this fills it in.
 *
 * Security: the page is served with a CSP "sandbox" (no scripts, opaque origin), so nothing in
 * it can act as the logged-in editor, and the body HTML is cleaned again before it's inserted.
 */
const esc = (s: unknown = '') =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')

const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
const longDate = (d: Date) => `${MONTHS[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`

const WP_UPLOADS = /^https?:\/\/(?:www\.)?canadiansme\.ca\/wp-content\/uploads\//i

const page = (status: number, body: string) =>
  new Response(body, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': "sandbox allow-popups allow-popups-to-escape-sandbox; script-src 'none'",
      'x-robots-tag': 'noindex, nofollow',
    },
  })

const message = (status: number, title: string, text: string) =>
  page(
    status,
    `<!doctype html><meta charset="utf-8"><title>${esc(title)}</title><body style="font:16px/1.5 system-ui,sans-serif;max-width:560px;margin:15vh auto;padding:0 20px"><h1 style="font-size:22px">${esc(title)}</h1><p>${esc(text)}</p></body>`,
  )

export const sitePreviewEndpoint: Endpoint = {
  path: '/site-preview',
  method: 'get',
  handler: async (req) => {
    if (!hasRole(req.user as never, 'admin', 'editor', 'author')) return message(401, 'Please log in', 'Log in to the CMS to preview drafts.')

    const collection = req.searchParams.get('collection') === 'pages' ? 'pages' : 'posts'
    const id = req.searchParams.get('id') || ''
    if (!/^\d+$/.test(id)) return message(400, 'Nothing to preview', 'Save the article first, then click Preview.')

    let doc: any // eslint-disable-line @typescript-eslint/no-explicit-any
    try {
      doc = await req.payload.findByID({ collection, id, draft: true, depth: 1, req, overrideAccess: false })
    } catch {
      return message(404, 'Not found', 'This article no longer exists.')
    }

    const site = getWebsiteURL()
    let template: string
    try {
      const res = await fetch(`${site}/_preview/`, { cache: 'no-store' })
      if (!res.ok) throw new Error(String(res.status))
      template = await res.text()
    } catch {
      return message(502, 'Website not reachable', `Could not load the website design from ${site}. Check WEBSITE_URL.`)
    }

    const body = sanitizeHtml(doc.useLegacyHtml && doc.legacyHtml ? doc.legacyHtml : lexicalToHtml(doc.content) || doc.legacyHtml || '')
    const cat = (collection === 'posts' && (doc.primaryCategory || doc.categories?.[0])) || null
    const author = collection === 'posts' ? doc.authors?.find((a: unknown) => a && typeof a === 'object') : null
    const media = doc.featuredImage && typeof doc.featuredImage === 'object' ? doc.featuredImage : null
    let image = media?.wpUrl || media?.sizes?.large?.url || media?.url || ''
    if (image && WP_UPLOADS.test(image)) image = image.replace(WP_UPLOADS, 'https://i0.wp.com/canadiansme.ca/wp-content/uploads/')
    else if (image && image.startsWith('/')) image = `${new URL(req.url || 'http://x').origin}${image}`
    const date = doc.publishedAt ? new Date(doc.publishedAt) : new Date()
    const status = doc._status === 'published' ? 'published version with your latest changes' : 'draft'

    const values: Record<string, string> = {
      TITLE: esc(doc.title || 'Untitled'),
      EXCERPT: esc(doc.excerpt || ''),
      SLUG: esc(doc.slug || ''),
      CATEGORY: esc(cat?.title || 'Uncategorised'),
      CATSLUG: esc(cat?.slug || 'latest-news'),
      AUTHOR: esc(author?.name || 'CanadianSME'),
      AUTHORSLUG: esc(author?.slug === 'admin' ? 'canadiansme' : author?.slug || 'canadiansme'),
      READ: esc(doc.readingTime || 1),
    }

    let html = template
      // Links and assets in the template are relative to /_preview/; point them at the website.
      .replace(/(href|src)="\.\.\//g, `$1="${site}/`)
      .replace(/<script type="application\/ld\+json">[\s\S]*?<\/script>/, '')
      .replace(/https:\/\/preview\.invalid\/%%IMAGE%%/g, image ? esc(image) : `${site}/assets/favicon.svg`)
      .replace(/datetime="2000-01-01T00:00:00"/g, `datetime="${date.toISOString()}"`)
      .replace(/January 1, 2000/g, longDate(date))
      .replace(/%%([A-Z]+)%%/g, (m, key: string) => (key === 'BODY' ? m : (values[key] ?? '')))
      .replace('%%BODY%%', () => body)
      .replace(/<body([^>]*)>/, `<body$1><div class="preview-banner">Preview: this is the ${status}. Visitors can't see these changes until you click Publish.</div>`)
    if (!image) html = html.replace(/<figure class="wrap post__hero">[\s\S]*?<\/figure>/, '')

    return page(200, html)
  },
}
