import type { Endpoint } from 'payload'

import { hasRole } from '../access'
import { writeAudit } from '../collections/AuditLogs'
import {
  counts,
  importAuthors,
  importCategories,
  importPagesPage,
  importPostsPage,
  importTags,
  preloadMaps,
  resetCounts,
  setConvertHtml,
} from '../import/wordpress'

/**
 * POST /api/wp-import   (admins only)
 *
 * Copies content from canadiansme.ca into this CMS, one step at a time so each request finishes
 * well within the server time limit. READ-ONLY on WordPress. Safe to repeat (updates, never
 * duplicates). Uses the CMS's own database and image-storage settings, so no keys need to be
 * copied anywhere else.
 *
 * Body: { "step": "taxonomies" | "authors" | "posts" | "pages", "page": 1, "perPage": 20 }
 * Response: { step, page, totalPages, total, read, counts }
 */
export const wpImportEndpoint: Endpoint = {
  path: '/wp-import',
  method: 'post',
  handler: async (req) => {
    if (!hasRole(req.user as never, 'admin')) {
      return Response.json({ error: 'Admins only' }, { status: 403 })
    }
    let body: any = {}
    try {
      body = (await req.json?.()) ?? {}
    } catch {
      body = {}
    }
    const step = String(body.step || '')
    const page = Math.max(1, Number(body.page) || 1)
    const perPage = Math.min(50, Math.max(1, Number(body.perPage) || 20))

    setConvertHtml(false)
    resetCounts()
    const payload = req.payload
    try {
      await preloadMaps(payload)
      let result: Record<string, unknown> = {}
      if (step === 'taxonomies') {
        await importCategories(payload)
        await importTags(payload)
      } else if (step === 'authors') {
        await importAuthors(payload)
      } else if (step === 'posts') {
        result = await importPostsPage(payload, page, perPage)
      } else if (step === 'pages') {
        result = await importPagesPage(payload, page, perPage)
      } else {
        return Response.json({ error: 'step must be taxonomies, authors, posts or pages' }, { status: 400 })
      }
      if (step !== 'posts' || page === 1) {
        await writeAudit(req, { action: 'create', collection: 'wp-import', summary: `WordPress import: ${step} page ${page}` })
      }
      return Response.json({ step, page, ...result, counts: { ...counts } })
    } catch (err) {
      return Response.json({ step, page, error: (err as Error).message, counts: { ...counts } }, { status: 500 })
    }
  },
}
