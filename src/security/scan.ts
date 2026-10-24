import type { Payload } from 'payload'

import { getDeploymentURL, getServerURL, getSiteURL, getWebsiteURL } from '../utilities/revalidate'
import {
  HitList,
  type RuleHit,
  type RuleId,
  type ScanOptions,
  type Severity,
  RULES,
  SEVERITIES,
  clip,
  compareSeverity,
  hasSpamTerm,
  hostOf,
  isOwnHost,
  isSuspiciousEmail,
  lexicalToScanHtml,
  scanFile,
  scanHtml,
  scanName,
  scanSocialLink,
  scanText,
  scanUrl,
} from './rules'

/**
 * Security scanner: reads documents page by page and runs the rules in ./rules.ts on every
 * field that could carry injected code, spam or rogue settings.
 *
 * READ-ONLY: it only calls find/count/findGlobal and never changes a document.
 * STATELESS: nothing is stored; results are returned to the caller (the admin view, the API
 * or the CLI script) which can download them as JSON/CSV.
 * SERVERLESS-FRIENDLY: one call scans one page of one collection, so each request stays far
 * below Vercel's time limit even for the ~8,800 imported articles.
 *
 * Callers must check that the user is an admin before calling (see endpoints/securityScan.ts);
 * the scan itself uses overrideAccess so it sees drafts and every account.
 */

export type ScanTarget =
  | 'posts'
  | 'pages'
  | 'categories'
  | 'tags'
  | 'authors'
  | 'media'
  | 'users'
  | 'redirects'
  | 'settings'

/** In the order the admin view runs them. */
export const SCAN_TARGETS: { target: ScanTarget; label: string; perPage: number }[] = [
  { target: 'posts', label: 'Articles', perPage: 25 },
  { target: 'pages', label: 'Pages', perPage: 25 },
  { target: 'categories', label: 'Categories', perPage: 100 },
  { target: 'tags', label: 'Tags', perPage: 100 },
  { target: 'authors', label: 'Authors', perPage: 100 },
  { target: 'media', label: 'Images & files', perPage: 100 },
  { target: 'users', label: 'Users & logins', perPage: 50 },
  { target: 'redirects', label: 'Redirects', perPage: 100 },
  { target: 'settings', label: 'Site settings & menus', perPage: 1 },
]

export const isScanTarget = (v: unknown): v is ScanTarget => SCAN_TARGETS.some((t) => t.target === v)

export type Finding = {
  /** Collection or global slug, e.g. "posts", "site-settings", "audit-logs". */
  collection: string
  id: string | number
  /** Title, name, file name or email, to recognise the document. */
  title: string
  slug?: string
  /** Field path, e.g. "legacyHtml", "content", "meta.description", "links.website". */
  field: string
  rule: RuleId
  severity: Severity
  /** At most 160 characters of raw text. Display it HTML-escaped (React does this). */
  excerpt: string
  /** How many times the rule matched this field. */
  count: number
  /** Where to fix it in the admin panel. */
  adminUrl: string
}

export type ScanPageResult = {
  target: ScanTarget
  page: number
  perPage: number
  totalPages: number
  totalDocs: number
  scanned: number
  findings: Finding[]
  durationMs: number
}

const MAX_PER_PAGE = 100

/** Hosts that count as "our own site" in addition to canadiansme.ca. */
export const ownHostsFromEnv = (): string[] =>
  [getSiteURL(), getWebsiteURL(), getServerURL(), getDeploymentURL()]
    .map((u) => hostOf(u || ''))
    .filter((h, i, a) => Boolean(h) && a.indexOf(h) === i)

const adminRoute = (payload: Payload): string => {
  const r = (payload.config as { routes?: { admin?: string } })?.routes?.admin
  return typeof r === 'string' && r ? r.replace(/\/$/, '') : '/admin'
}

type DocLike = Record<string, any>

const labelOf = (doc: DocLike): string =>
  clip(String(doc.title || doc.name || doc.filename || doc.email || doc.from || doc.slug || `#${doc.id}`), 120)

/** Builds findings for one document. */
class DocFindings {
  out: Finding[] = []
  constructor(
    readonly collection: string,
    readonly doc: DocLike,
    readonly adminUrl: string,
  ) {}

  push(field: string, hits: RuleHit[]): void {
    for (const h of hits) {
      this.out.push({
        collection: this.collection,
        id: this.doc.id ?? '',
        title: labelOf(this.doc),
        slug: typeof this.doc.slug === 'string' ? this.doc.slug : undefined,
        field,
        rule: h.rule,
        severity: h.severity,
        excerpt: clip(h.excerpt, 160),
        count: h.count,
        adminUrl: this.adminUrl,
      })
    }
  }

  one(field: string, rule: RuleId, excerpt: string, severity: Severity = RULES[rule].severity): void {
    this.push(field, [{ rule, severity, excerpt, count: 1 }])
  }
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '')

const canonicalHits = (url: string, opts: ScanOptions): RuleHit[] => {
  const v = url.trim()
  if (!v) return []
  const hits = new HitList()
  hits.addAll(scanUrl(v, opts))
  const host = hostOf(v)
  if (host && !isOwnHost(host, opts.ownHosts)) hits.add('canonical-hijack', v)
  return hits.list()
}

/** Article / page / category SEO fields added by the SEO plugin. */
const scanMeta = (f: DocFindings, meta: unknown, opts: ScanOptions) => {
  if (!meta || typeof meta !== 'object') return
  const m = meta as Record<string, unknown>
  f.push('meta.title', scanName(str(m.title), opts))
  f.push('meta.description', scanText(str(m.description), opts))
  f.push('meta.canonicalUrl', canonicalHits(str(m.canonicalUrl), opts))
}

// ---------------------------------------------------------------------------------------------
// Collections with rich content
// ---------------------------------------------------------------------------------------------

const scanContentDoc = (collection: 'posts' | 'pages', doc: DocLike, base: string, opts: ScanOptions): Finding[] => {
  const f = new DocFindings(collection, doc, `${base}/collections/${collection}/${doc.id}`)
  f.push('title', scanName(str(doc.title), opts))
  f.push('slug', scanName(str(doc.slug), opts))
  f.push('excerpt', scanText(str(doc.excerpt), opts))
  f.push('legacyHtml', scanHtml(str(doc.legacyHtml), opts))
  if (doc.content) f.push('content', scanHtml(lexicalToScanHtml(doc.content), opts))
  f.push('sourceUrl', scanUrl(str(doc.sourceUrl), opts))
  scanMeta(f, doc.meta, opts)
  return f.out
}

const scanTaxonomyDoc = (collection: 'categories' | 'tags', doc: DocLike, base: string, opts: ScanOptions): Finding[] => {
  const f = new DocFindings(collection, doc, `${base}/collections/${collection}/${doc.id}`)
  f.push('title', scanName(str(doc.title), opts))
  f.push('slug', scanName(str(doc.slug), opts))
  f.push('description', scanText(str(doc.description), opts))
  scanMeta(f, doc.meta, opts)
  return f.out
}

const scanAuthorDoc = (doc: DocLike, base: string, opts: ScanOptions): Finding[] => {
  const f = new DocFindings('authors', doc, `${base}/collections/authors/${doc.id}`)
  f.push('name', scanName(str(doc.name), opts))
  f.push('slug', scanName(str(doc.slug), opts))
  f.push('jobTitle', scanName(str(doc.jobTitle), opts))
  f.push('bio', scanText(str(doc.bio), opts))
  const links = (doc.links && typeof doc.links === 'object' ? doc.links : {}) as Record<string, unknown>
  for (const key of ['website', 'linkedin', 'x', 'instagram']) {
    const url = str(links[key])
    if (!url) continue
    if (key === 'website') f.push(`links.${key}`, scanUrl(url, { ...opts, requireHttps: true }))
    else f.push(`links.${key}`, scanSocialLink(key, url, opts))
  }
  return f.out
}

const scanMediaDoc = (doc: DocLike, base: string, opts: ScanOptions): Finding[] => {
  const f = new DocFindings('media', doc, `${base}/collections/media/${doc.id}`)
  f.push('filename', scanFile({ filename: doc.filename, mimeType: doc.mimeType, wpUrl: doc.wpUrl }, opts))
  f.push('alt', scanText(str(doc.alt), opts))
  f.push('caption', scanText(str(doc.caption), opts))
  f.push('credit', scanName(str(doc.credit), opts))
  return f.out
}

const scanRedirectDoc = (doc: DocLike, base: string, opts: ScanOptions): Finding[] => {
  const f = new DocFindings('redirects', doc, `${base}/collections/redirects/${doc.id}`)
  const from = str(doc.from)
  if (from && hasSpamTerm(from.replace(/[\/\-_+.]+/g, ' '))) f.one('from', 'spam-redirect-path', from)
  const to = (doc.to && typeof doc.to === 'object' ? doc.to : {}) as Record<string, unknown>
  const url = to.type === 'custom' || !to.reference ? str(to.url).trim() : ''
  if (url) {
    const hits = scanUrl(url, { ...opts, requireHttps: true })
    const shown = `${from || '?'} → ${url}`
    const bad = hits.filter((h) =>
      ['dangerous-url', 'suspicious-domain', 'ip-address-link', 'url-shortener', 'spam-link'].includes(h.rule),
    )
    if (bad.length) f.one('to.url', 'suspicious-redirect', `${shown} (${bad.map((h) => RULES[h.rule].title).join(', ')})`)
    const host = hostOf(url)
    if (host && !isOwnHost(host, opts.ownHosts) && !bad.length) f.one('to.url', 'external-redirect', shown)
    f.push('to.url', hits.filter((h) => h.rule === 'insecure-url'))
  }
  return f.out
}

// ---------------------------------------------------------------------------------------------
// Users and logins (never returns password hashes, salts, tokens or API keys)
// ---------------------------------------------------------------------------------------------

const DAY = 24 * 60 * 60 * 1000

const scanUsersPage = async (
  payload: Payload,
  page: number,
  perPage: number,
  base: string,
): Promise<{ findings: Finding[]; totalPages: number; totalDocs: number; scanned: number }> => {
  // No `select` here on purpose: auth fields (lockUntil, enableAPIKey) are read from the full
  // document, but only the explicitly picked fields below ever leave this function.
  const res = await payload.find({
    collection: 'users',
    page,
    limit: perPage,
    depth: 0,
    sort: 'createdAt',
    overrideAccess: true,
  })
  const now = Date.now()
  const findings: Finding[] = []

  for (const raw of res.docs as unknown as DocLike[]) {
    // Only safe fields are copied; everything else on the user document is dropped here.
    const u: DocLike = {
      id: raw.id,
      name: str(raw.name),
      email: str(raw.email),
      roles: Array.isArray(raw.roles) ? (raw.roles as string[]) : [],
      createdAt: str(raw.createdAt),
      lockUntil: str(raw.lockUntil),
      enableAPIKey: Boolean(raw.enableAPIKey),
    }
    const f = new DocFindings('users', { ...u, title: `${u.name || u.email} <${u.email}>` }, `${base}/collections/users/${u.id}`)
    const roles = u.roles as string[]
    const isAdmin = roles.includes('admin')
    const automation = roles.includes('automation')
    const created = Date.parse(u.createdAt) || now

    if (isAdmin) {
      f.one('roles', 'admin-account', `${u.email} — roles: ${roles.join(', ')} — created ${u.createdAt.slice(0, 10)}`)
      if (now - created < 30 * DAY) f.one('createdAt', 'new-admin', `${u.email} created ${u.createdAt.slice(0, 10)}`)
    }
    if (automation && roles.length > 1) f.one('roles', 'mixed-automation-role', `${u.email} — roles: ${roles.join(', ')}`)
    if (u.enableAPIKey && !automation) f.one('enableAPIKey', 'api-key-on-person', `${u.email} has an API key enabled`)
    if (isSuspiciousEmail(u.email)) f.one('email', 'suspicious-email', u.email)
    if (u.lockUntil && Date.parse(u.lockUntil) > now) f.one('lockUntil', 'account-locked', `${u.email} locked until ${u.lockUntil}`)

    if (!(automation && roles.length === 1) && now - created > 30 * DAY) {
      try {
        const logins = await payload.count({
          collection: 'audit-logs',
          where: { and: [{ action: { equals: 'login' } }, { user: { equals: u.id } }] },
          overrideAccess: true,
        })
        if (logins.totalDocs === 0) {
          f.one('lastLogin', 'never-logged-in', `${u.email} (created ${u.createdAt.slice(0, 10)})`, isAdmin ? 'medium' : 'low')
        }
      } catch {
        // activity log unavailable: skip this check
      }
    }
    findings.push(...f.out)
  }

  if (page === 1) {
    const adminsUrl = `${base}/collections/users?where[roles][contains]=admin`
    try {
      const admins = await payload.count({ collection: 'users', where: { roles: { contains: 'admin' } }, overrideAccess: true })
      if (admins.totalDocs > 3) {
        findings.push({
          collection: 'users',
          id: '',
          title: `${admins.totalDocs} admin accounts`,
          field: 'roles',
          rule: 'many-admins',
          severity: 'medium',
          excerpt: `${admins.totalDocs} accounts have the Admin role`,
          count: admins.totalDocs,
          adminUrl: adminsUrl,
        })
      }
    } catch {
      // ignore
    }
    findings.push(...(await scanFailedLogins(payload, base)))
  }

  return { findings, totalPages: res.totalPages || 1, totalDocs: res.totalDocs, scanned: res.docs.length }
}

/** Failed logins in the last 7 days, grouped by email and by IP (from the activity log). */
const scanFailedLogins = async (payload: Payload, base: string): Promise<Finding[]> => {
  const since = new Date(Date.now() - 7 * DAY).toISOString()
  let docs: DocLike[] = []
  try {
    const res = await payload.find({
      collection: 'audit-logs',
      where: { and: [{ action: { equals: 'login-failed' } }, { createdAt: { greater_than: since } }] },
      limit: 5000,
      depth: 0,
      sort: '-createdAt',
      select: { userEmail: true, ip: true, createdAt: true } as any,
      overrideAccess: true,
    })
    docs = res.docs as unknown as DocLike[]
  } catch {
    return []
  }
  const byEmail = new Map<string, number>()
  const byIp = new Map<string, number>()
  for (const d of docs) {
    const e = str(d.userEmail).toLowerCase().slice(0, 200)
    const ip = str(d.ip).slice(0, 64)
    if (e) byEmail.set(e, (byEmail.get(e) || 0) + 1)
    if (ip) byIp.set(ip, (byIp.get(ip) || 0) + 1)
  }
  const logUrl = (key: 'userEmail' | 'ip', value: string) =>
    `${base}/collections/audit-logs?where[action][equals]=login-failed&where[${key}][equals]=${encodeURIComponent(value)}`
  const out: Finding[] = []
  for (const [email, n] of byEmail) {
    if (n < 5) continue
    out.push({
      collection: 'audit-logs',
      id: '',
      title: email,
      field: 'userEmail',
      rule: 'failed-logins',
      severity: n >= 20 ? 'high' : 'medium',
      excerpt: `${n} failed logins for ${email} in the last 7 days`,
      count: n,
      adminUrl: logUrl('userEmail', email),
    })
  }
  for (const [ip, n] of byIp) {
    if (n < 10) continue
    out.push({
      collection: 'audit-logs',
      id: '',
      title: ip,
      field: 'ip',
      rule: 'brute-force-ip',
      severity: 'high',
      excerpt: `${n} failed logins from ${ip} in the last 7 days`,
      count: n,
      adminUrl: logUrl('ip', ip),
    })
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------------------------

const scanSettings = async (payload: Payload, base: string, opts: ScanOptions): Promise<{ findings: Finding[]; scanned: number }> => {
  const findings: Finding[] = []
  let scanned = 0

  try {
    const s = (await payload.findGlobal({ slug: 'site-settings', depth: 0, overrideAccess: true })) as unknown as DocLike
    scanned++
    const f = new DocFindings('site-settings', { id: 'site-settings', title: 'Site settings' }, `${base}/globals/site-settings`)
    for (const key of ['siteName', 'tagline', 'titleSuffix']) f.push(key, scanName(str(s[key]), opts))
    f.push('defaultDescription', scanText(str(s.defaultDescription), opts))
    if (str(s.contactEmail) && isSuspiciousEmail(str(s.contactEmail))) f.one('contactEmail', 'suspicious-email', str(s.contactEmail))
    f.push('subscribeUrl', scanUrl(str(s.subscribeUrl), { ...opts, requireHttps: true }))
    f.push('articleFooterHtml', scanHtml(str(s.articleFooterHtml), opts))
    if (s.organizationSchema !== undefined && s.organizationSchema !== null) {
      // JSON-LD is printed inside a <script> tag on the website: "</script>" in it would break out.
      let json = ''
      try {
        json = JSON.stringify(s.organizationSchema)
      } catch {
        json = ''
      }
      f.push('organizationSchema', scanText(json, opts))
      if (/<\/?script/i.test(json)) f.one('organizationSchema', 'script-tag', clip(json))
    }
    const social = (s.social && typeof s.social === 'object' ? s.social : {}) as Record<string, unknown>
    for (const key of Object.keys(social)) {
      if (key === 'id') continue
      f.push(`social.${key}`, scanSocialLink(key, str(social[key]), opts))
    }
    findings.push(...f.out)
  } catch (err) {
    findings.push(errorFinding('site-settings', 'site-settings', `${base}/globals/site-settings`, err))
  }

  try {
    const n = (await payload.findGlobal({ slug: 'navigation', depth: 0, overrideAccess: true })) as unknown as DocLike
    scanned++
    const f = new DocFindings('navigation', { id: 'navigation', title: 'Navigation' }, `${base}/globals/navigation`)
    const walk = (items: unknown, path: string) => {
      if (!Array.isArray(items)) return
      items.forEach((it: DocLike, i: number) => {
        if (!it || typeof it !== 'object') return
        const p = `${path}[${i}]`
        f.push(`${p}.label`, scanName(str(it.label), opts))
        const url = str(it.url).trim()
        if (url) f.push(`${p}.url`, scanUrl(url, { ...opts, requireHttps: true, linkText: str(it.label) }))
        walk(it.children, `${p}.children`)
      })
    }
    walk(n.header, 'header')
    walk(n.footer, 'footer')
    findings.push(...f.out)
  } catch (err) {
    findings.push(errorFinding('navigation', 'navigation', `${base}/globals/navigation`, err))
  }

  return { findings, scanned }
}

const errorFinding = (collection: string, id: string | number, adminUrl: string, err: unknown): Finding => ({
  collection,
  id,
  title: String(id),
  field: '-',
  rule: 'scan-error',
  severity: 'low',
  excerpt: clip(`Could not scan: ${(err as Error)?.message || String(err)}`),
  count: 1,
  adminUrl,
})

// ---------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------

/** Fields read per collection (keeps queries small: no relationships, no unused columns). */
const SELECT: Partial<Record<ScanTarget, Record<string, true>>> = {
  posts: { title: true, slug: true, excerpt: true, legacyHtml: true, content: true, sourceUrl: true, meta: true },
  pages: { title: true, slug: true, legacyHtml: true, content: true, meta: true },
  categories: { title: true, slug: true, description: true, meta: true },
  tags: { title: true, slug: true, description: true },
  authors: { name: true, slug: true, jobTitle: true, bio: true, links: true },
  media: { filename: true, mimeType: true, wpUrl: true, alt: true, caption: true, credit: true },
  redirects: { from: true, to: true, type: true },
}

/**
 * Scans one page of one target. `perPage` is capped at 100 (25 is a good size for articles,
 * whose HTML can be large).
 */
export const scanTarget = async (
  payload: Payload,
  target: ScanTarget,
  page = 1,
  perPage?: number,
  options: ScanOptions = {},
): Promise<ScanPageResult> => {
  const started = Date.now()
  const base = adminRoute(payload)
  const opts: ScanOptions = { ...options, ownHosts: [...(options.ownHosts || []), ...ownHostsFromEnv()] }
  const def = SCAN_TARGETS.find((t) => t.target === target)!
  const limit = Math.min(MAX_PER_PAGE, Math.max(1, Math.floor(Number(perPage) || def.perPage)))
  const p = Math.max(1, Math.floor(Number(page) || 1))

  const done = (r: { findings: Finding[]; totalPages: number; totalDocs: number; scanned: number }): ScanPageResult => ({
    target,
    page: p,
    perPage: limit,
    totalPages: Math.max(1, r.totalPages),
    totalDocs: r.totalDocs,
    scanned: r.scanned,
    findings: r.findings.sort((a, b) => compareSeverity(a.severity, b.severity)),
    durationMs: Date.now() - started,
  })

  if (target === 'settings') {
    const r = await scanSettings(payload, base, opts)
    return done({ findings: r.findings, totalPages: 1, totalDocs: r.scanned, scanned: r.scanned })
  }
  if (target === 'users') {
    return done(await scanUsersPage(payload, p, limit, base))
  }

  const res = await payload.find({
    collection: target as any,
    page: p,
    limit,
    depth: 0,
    sort: 'id',
    select: SELECT[target] as any,
    overrideAccess: true,
  })

  const findings: Finding[] = []
  for (const doc of res.docs as unknown as DocLike[]) {
    try {
      if (target === 'posts' || target === 'pages') findings.push(...scanContentDoc(target, doc, base, opts))
      else if (target === 'categories' || target === 'tags') findings.push(...scanTaxonomyDoc(target, doc, base, opts))
      else if (target === 'authors') findings.push(...scanAuthorDoc(doc, base, opts))
      else if (target === 'media') findings.push(...scanMediaDoc(doc, base, opts))
      else if (target === 'redirects') findings.push(...scanRedirectDoc(doc, base, opts))
    } catch (err) {
      findings.push(errorFinding(target, doc?.id ?? '', `${base}/collections/${target}/${doc?.id ?? ''}`, err))
    }
  }

  return done({ findings, totalPages: res.totalPages || 1, totalDocs: res.totalDocs, scanned: res.docs.length })
}

export type ScanSummary = {
  total: number
  bySeverity: Record<Severity, number>
  byRule: Partial<Record<RuleId, number>>
}

export const summarize = (findings: Finding[]): ScanSummary => {
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>
  const byRule: Partial<Record<RuleId, number>> = {}
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1
    byRule[f.rule] = (byRule[f.rule] || 0) + 1
  }
  return { total: findings.length, bySeverity, byRule }
}
