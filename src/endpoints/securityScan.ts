import type { Endpoint } from 'payload'

import { hasRole } from '../access'
import { writeAudit } from '../collections/AuditLogs'
import { SEVERITIES } from '../security/rules'
import { SCAN_TARGETS, isScanTarget, scanTarget } from '../security/scan'

/**
 * POST /api/security-scan   (admins only, read-only)
 *
 * Scans one page of one collection for leftovers of WordPress hacks (injected scripts, hidden
 * spam links, obfuscated code, rogue redirects and accounts). See src/security/rules.ts for
 * every rule and SECURITY.md for how to read the results. Nothing is changed or stored; the
 * admin view at /admin/security calls this page by page and builds the report in the browser.
 *
 * Body:     { "target": "posts" | "pages" | "categories" | "tags" | "authors" | "media"
 *                        | "users" | "redirects" | "settings", "page": 1, "perPage": 25 }
 * Response: { target, page, perPage, totalPages, totalDocs, scanned, findings: Finding[], durationMs }
 *
 * Body:     { "target": "report", "summary": { "critical": 0, "high": 2, "medium": 5, "low": 9 } }
 *           Records "security scan finished" with these counts in the Activity log.
 */
export const securityScanEndpoint: Endpoint = {
  path: '/security-scan',
  method: 'post',
  handler: async (req) => {
    if (!req.user) return Response.json({ error: 'Log in first' }, { status: 401 })
    if (!hasRole(req.user as never, 'admin')) {
      return Response.json({ error: 'Admins only' }, { status: 403 })
    }
    let body: any = {}
    try {
      body = (await req.json?.()) ?? {}
    } catch {
      body = {}
    }
    const headers = { 'Cache-Control': 'no-store' }
    const target = String(body.target || '')

    if (target === 'report') {
      const s = (body.summary && typeof body.summary === 'object' ? body.summary : {}) as Record<string, unknown>
      const parts = SEVERITIES.map((sev) => `${Math.max(0, Math.floor(Number(s[sev]) || 0))} ${sev}`)
      await writeAudit(req, {
        action: 'create',
        collection: 'security-scan',
        summary: `Security scan finished: ${parts.join(', ')}`,
      })
      return Response.json({ ok: true }, { headers })
    }

    if (!isScanTarget(target)) {
      return Response.json(
        { error: `target must be one of: ${SCAN_TARGETS.map((t) => t.target).join(', ')}` },
        { status: 400, headers },
      )
    }
    const page = Math.max(1, Math.floor(Number(body.page) || 1))
    const perPage = body.perPage === undefined ? undefined : Number(body.perPage)

    try {
      const result = await scanTarget(req.payload, target, page, perPage)
      if (page === 1 && target === SCAN_TARGETS[0].target) {
        await writeAudit(req, { action: 'create', collection: 'security-scan', summary: 'Security scan started' })
      }
      return Response.json(result, { headers })
    } catch (err) {
      req.payload.logger.error(`Security scan failed (${target} page ${page}): ${(err as Error).message}`)
      return Response.json({ target, page, error: (err as Error).message }, { status: 500, headers })
    }
  },
}
