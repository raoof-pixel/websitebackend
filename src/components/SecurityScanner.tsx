'use client'

import React, { useCallback, useMemo, useRef, useState } from 'react'

import { RULES, SEVERITIES, type RuleGroup, type RuleId, type RuleInfo, type Severity } from '../security/rules'

/**
 * The "Security scan" screen. Runs every scan target page by page through
 * POST /api/security-scan (each request is small, so it works on Vercel's time limits),
 * then shows a summary, a filterable findings table and JSON/CSV downloads.
 * Read-only: nothing is changed by scanning. Results live only in this browser tab.
 */

type Finding = {
  collection: string
  id: string | number
  title: string
  slug?: string
  field: string
  rule: RuleId
  severity: Severity
  excerpt: string
  count: number
  adminUrl: string
}

type PageResult = {
  target: string
  page: number
  totalPages: number
  totalDocs: number
  scanned: number
  findings: Finding[]
  error?: string
}

// Same list and order as SCAN_TARGETS in security/scan.ts (kept here so the client bundle
// doesn't pull in server code).
const TARGETS: { target: string; label: string; perPage: number }[] = [
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

const GROUP_LABELS: Record<RuleGroup, string> = {
  code: 'Injected code',
  links: 'Links',
  spam: 'Spam',
  media: 'Uploads',
  users: 'Users & logins',
  redirects: 'Redirects',
  settings: 'Settings',
}

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

const ROWS_STEP = 200

type Status = 'idle' | 'running' | 'stopped' | 'done'

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** CSV cell: quoted, and protected against spreadsheet formula injection (=, +, -, @). */
const csvCell = (v: unknown) => {
  let s = String(v ?? '')
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`
  return `"${s.replace(/"/g, '""')}"`
}

const download = (name: string, type: string, content: string) => {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const SecurityScanner = ({ apiRoute = '/api', adminRoute = '/admin' }: { apiRoute?: string; adminRoute?: string }) => {
  const [status, setStatus] = useState<Status>('idle')
  const [selected, setSelected] = useState<string[]>(TARGETS.map((t) => t.target))
  const [findings, setFindings] = useState<Finding[]>([])
  const [progress, setProgress] = useState({ targetIndex: 0, targetCount: 0, page: 0, totalPages: 0, label: '', scanned: 0 })
  const [errors, setErrors] = useState<string[]>([])
  const [startedAt, setStartedAt] = useState<string>('')
  const [finishedAt, setFinishedAt] = useState<string>('')
  const [scannedByTarget, setScannedByTarget] = useState<Record<string, number>>({})
  const stopRef = useRef(false)

  // Filters
  const [fSeverity, setFSeverity] = useState<string>('')
  const [fRule, setFRule] = useState<string>('')
  const [fCollection, setFCollection] = useState<string>('')
  const [fText, setFText] = useState<string>('')
  const [rows, setRows] = useState(ROWS_STEP)
  const [showRules, setShowRules] = useState(false)

  const fetchPage = useCallback(
    async (target: string, page: number, perPage: number): Promise<PageResult> => {
      let lastError = ''
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const res = await fetch(`${apiRoute}/security-scan`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, page, perPage }),
          })
          const json = (await res.json().catch(() => ({}))) as PageResult & { error?: string }
          if (res.status === 401 || res.status === 403) throw new Error(json.error || `Not allowed (${res.status})`)
          if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`)
          return json
        } catch (err) {
          lastError = (err as Error).message
          if (/not allowed|log in|admins only/i.test(lastError)) break
          await sleep(800 * (attempt + 1))
        }
      }
      return { target, page, totalPages: page, totalDocs: 0, scanned: 0, findings: [], error: lastError || 'Request failed' }
    },
    [apiRoute],
  )

  const run = useCallback(async () => {
    stopRef.current = false
    setStatus('running')
    setFindings([])
    setErrors([])
    setScannedByTarget({})
    setRows(ROWS_STEP)
    setStartedAt(new Date().toISOString())
    setFinishedAt('')
    const list = TARGETS.filter((t) => selected.includes(t.target))
    const all: Finding[] = []
    let scannedTotal = 0

    for (let i = 0; i < list.length; i++) {
      const t = list[i]
      let page = 1
      let totalPages = 1
      do {
        if (stopRef.current) break
        setProgress({ targetIndex: i, targetCount: list.length, page, totalPages, label: t.label, scanned: scannedTotal })
        const r = await fetchPage(t.target, page, t.perPage)
        if (r.error) {
          setErrors((e) => [...e, `${t.label}, page ${page}: ${r.error}`])
          if (/not allowed|log in|admins only/i.test(r.error)) {
            stopRef.current = true
            break
          }
        } else {
          totalPages = Math.max(1, r.totalPages || 1)
          scannedTotal += r.scanned || 0
          setScannedByTarget((s) => ({ ...s, [t.target]: (s[t.target] || 0) + (r.scanned || 0) }))
          if (r.findings?.length) {
            all.push(...r.findings)
            setFindings([...all])
          }
        }
        page++
      } while (page <= totalPages)
      if (stopRef.current) break
    }

    setProgress((p) => ({ ...p, targetIndex: list.length, scanned: scannedTotal }))
    setFinishedAt(new Date().toISOString())
    const stopped = stopRef.current
    setStatus(stopped ? 'stopped' : 'done')

    if (!stopped) {
      const summary = Object.fromEntries(SEVERITIES.map((s) => [s, all.filter((f) => f.severity === s).length]))
      fetch(`${apiRoute}/security-scan`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: 'report', summary }),
      }).catch(() => undefined)
    }
  }, [apiRoute, fetchPage, selected])

  const stop = () => {
    stopRef.current = true
  }

  // ---- derived data ----
  const bySeverity = useMemo(() => {
    const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const f of findings) out[f.severity]++
    return out
  }, [findings])

  const byRule = useMemo(() => {
    const m = new Map<RuleId, { count: number; severity: Severity }>()
    for (const f of findings) {
      const prev = m.get(f.rule)
      if (!prev) m.set(f.rule, { count: 1, severity: f.severity })
      else {
        prev.count++
        if (SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(prev.severity)) prev.severity = f.severity
      }
    }
    return [...m.entries()].sort(
      (a, b) => SEVERITIES.indexOf(a[1].severity) - SEVERITIES.indexOf(b[1].severity) || b[1].count - a[1].count,
    )
  }, [findings])

  const collections = useMemo(() => [...new Set(findings.map((f) => f.collection))].sort(), [findings])

  const filtered = useMemo(() => {
    const q = fText.trim().toLowerCase()
    return findings
      .filter((f) => (!fSeverity || f.severity === fSeverity) && (!fRule || f.rule === fRule) && (!fCollection || f.collection === fCollection))
      .filter((f) => !q || `${f.title} ${f.slug || ''} ${f.field} ${f.excerpt} ${f.id}`.toLowerCase().includes(q))
      .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
  }, [findings, fSeverity, fRule, fCollection, fText])

  const docsWithFindings = useMemo(() => new Set(findings.map((f) => `${f.collection}:${f.id}`)).size, [findings])

  const pct = useMemo(() => {
    if (status === 'done') return 100
    if (!progress.targetCount) return 0
    const within = progress.totalPages ? (progress.page - 1) / progress.totalPages : 0
    return Math.min(100, Math.round(((progress.targetIndex + within) / progress.targetCount) * 100))
  }, [progress, status])

  const report = () => ({
    generatedAt: finishedAt || new Date().toISOString(),
    startedAt,
    complete: status === 'done',
    targets: selected,
    scanned: scannedByTarget,
    summary: { total: findings.length, bySeverity, byRule: Object.fromEntries(byRule.map(([r, v]) => [r, v.count])) },
    errors,
    findings,
  })

  const stamp = () => (finishedAt || new Date().toISOString()).slice(0, 16).replace(/[:T]/g, '-')

  const downloadJson = () => download(`security-scan-${stamp()}.json`, 'application/json', JSON.stringify(report(), null, 2))

  const downloadCsv = () => {
    const head = ['severity', 'rule', 'rule_title', 'collection', 'id', 'title', 'slug', 'field', 'count', 'excerpt', 'admin_url']
    const origin = typeof window !== 'undefined' ? window.location.origin : ''
    const lines = [head.join(',')]
    for (const f of filtered) {
      lines.push(
        [f.severity, f.rule, RULES[f.rule]?.title, f.collection, f.id, f.title, f.slug, f.field, f.count, f.excerpt, `${origin}${f.adminUrl}`]
          .map(csvCell)
          .join(','),
      )
    }
    download(`security-scan-${stamp()}.csv`, 'text/csv;charset=utf-8', `﻿${lines.join('\r\n')}`)
  }

  const toggleTarget = (t: string) =>
    setSelected((s) => (s.includes(t) ? s.filter((x) => x !== t) : TARGETS.map((x) => x.target).filter((x) => x === t || s.includes(x))))

  const running = status === 'running'
  const groups = useMemo(() => {
    const g = new Map<RuleGroup, RuleInfo[]>()
    for (const info of Object.values(RULES)) {
      if (info.id === 'scan-error') continue
      g.set(info.group, [...(g.get(info.group) || []), info])
    }
    return [...g.entries()]
  }, [])

  return (
    <section className="csme-sec">
      <div className="csme-sec__hero">
        <div>
          <p className="csme-dash__eyebrow">Security</p>
          <h1 className="csme-sec__title">
            Security <span>scan</span>
          </h1>
          <p className="csme-sec__sub">
            Looks through every article, page, category, tag, author, upload, user, redirect and setting for the
            usual leftovers of a WordPress hack: injected scripts and iframes, hidden spam links, obfuscated code,
            spam keywords, suspicious redirects and rogue accounts. Read-only: nothing is changed.
          </p>
        </div>
        <div className="csme-dash__actions">
          {running ? (
            <button type="button" className="csme-btn csme-btn--ghost" onClick={stop}>
              Stop
            </button>
          ) : (
            <button type="button" className="csme-btn csme-btn--lime" onClick={run} disabled={!selected.length}>
              {status === 'idle' ? 'Start scan' : 'Scan again'}
            </button>
          )}
          <button type="button" className="csme-btn csme-btn--ghost" onClick={() => setShowRules((v) => !v)}>
            {showRules ? 'Hide rules' : 'What is checked?'}
          </button>
        </div>
      </div>

      <div className="csme-sec__targets" role="group" aria-label="What to scan">
        {TARGETS.map((t) => (
          <label key={t.target} className={`csme-sec__chip${selected.includes(t.target) ? ' is-on' : ''}`}>
            <input type="checkbox" checked={selected.includes(t.target)} disabled={running} onChange={() => toggleTarget(t.target)} />
            {t.label}
            {scannedByTarget[t.target] !== undefined ? <span className="csme-sec__chip-count">{scannedByTarget[t.target].toLocaleString('en-CA')}</span> : null}
          </label>
        ))}
      </div>

      {status !== 'idle' && (
        <div className="csme-sec__progress" aria-live="polite">
          <div className="csme-sec__bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
            <span style={{ width: `${pct}%` }} />
          </div>
          <p className="csme-sec__progress-text">
            {running
              ? `Scanning ${progress.label}${progress.totalPages > 1 ? ` — page ${progress.page} of ${progress.totalPages}` : ''} · ${progress.scanned.toLocaleString('en-CA')} items checked`
              : status === 'stopped'
                ? `Stopped. ${progress.scanned.toLocaleString('en-CA')} items checked; results below are partial.`
                : `Finished: ${progress.scanned.toLocaleString('en-CA')} items checked, ${findings.length.toLocaleString('en-CA')} findings in ${docsWithFindings.toLocaleString('en-CA')} items.`}
          </p>
          {errors.length > 0 && (
            <details className="csme-sec__errors">
              <summary>{errors.length} page(s) could not be scanned</summary>
              <ul>
                {errors.slice(0, 50).map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}

      {showRules && (
        <div className="csme-sec__rules">
          <p className="csme-sec__note">
            Spam words only count inside links, in clusters of several different phrases, or in short fields like
            titles and names, so normal business reporting about loans, crypto or pharmacies is not flagged. Every
            finding is a lead to review, not proof of a hack: open the item, check the excerpt, and clean it up in the
            editor if it is spam.
          </p>
          {groups.map(([group, list]) => (
            <div key={group} className="csme-sec__rule-group">
              <h3>{GROUP_LABELS[group]}</h3>
              <dl>
                {list.map((info) => (
                  <div key={info.id} className="csme-sec__rule">
                    <dt>
                      <span className={`csme-sev csme-sev--${info.severity}`}>{SEVERITY_LABEL[info.severity]}</span> {info.title}{' '}
                      <code>{info.id}</code>
                    </dt>
                    <dd>
                      {info.description}
                      {info.falsePositives ? <em> Harmless when: {info.falsePositives}</em> : null}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          ))}
        </div>
      )}

      {status !== 'idle' && (
        <>
          <div className="csme-sec__stats">
            {SEVERITIES.map((s) => (
              <button
                type="button"
                key={s}
                className={`csme-sec__stat csme-sec__stat--${s}${fSeverity === s ? ' is-active' : ''}`}
                onClick={() => {
                  setFSeverity(fSeverity === s ? '' : s)
                  setRows(ROWS_STEP)
                }}
              >
                <span className="csme-stat__value">{bySeverity[s].toLocaleString('en-CA')}</span>
                <span className="csme-stat__label">{SEVERITY_LABEL[s]}</span>
              </button>
            ))}
          </div>

          {byRule.length > 0 && (
            <div className="csme-sec__byrule">
              <h3>By rule</h3>
              <ul>
                {byRule.map(([rule, v]) => (
                  <li key={rule}>
                    <button
                      type="button"
                      className={fRule === rule ? 'is-active' : ''}
                      onClick={() => {
                        setFRule(fRule === rule ? '' : rule)
                        setRows(ROWS_STEP)
                      }}
                      title={RULES[rule]?.description}
                    >
                      <span className={`csme-sev csme-sev--${v.severity}`}>{SEVERITY_LABEL[v.severity]}</span>
                      <span className="csme-sec__byrule-name">{RULES[rule]?.title || rule}</span>
                      <span className="csme-sec__byrule-count">{v.count.toLocaleString('en-CA')}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="csme-sec__toolbar">
            <select value={fSeverity} onChange={(e) => { setFSeverity(e.target.value); setRows(ROWS_STEP) }} aria-label="Severity">
              <option value="">All severities</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABEL[s]}
                </option>
              ))}
            </select>
            <select value={fRule} onChange={(e) => { setFRule(e.target.value); setRows(ROWS_STEP) }} aria-label="Rule">
              <option value="">All rules</option>
              {byRule.map(([rule]) => (
                <option key={rule} value={rule}>
                  {RULES[rule]?.title || rule}
                </option>
              ))}
            </select>
            <select value={fCollection} onChange={(e) => { setFCollection(e.target.value); setRows(ROWS_STEP) }} aria-label="Collection">
              <option value="">Everywhere</option>
              {collections.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
            <input
              type="search"
              placeholder="Search title, field, excerpt…"
              value={fText}
              onChange={(e) => { setFText(e.target.value); setRows(ROWS_STEP) }}
              aria-label="Search findings"
            />
            <span className="csme-sec__toolbar-spacer" />
            <button type="button" className="csme-btn csme-btn--outline" onClick={downloadJson} disabled={!findings.length && status !== 'done'}>
              Download JSON
            </button>
            <button type="button" className="csme-btn csme-btn--outline" onClick={downloadCsv} disabled={!filtered.length}>
              Download CSV
            </button>
          </div>

          {filtered.length === 0 ? (
            <p className="csme-sec__empty">
              {running ? 'Nothing found yet…' : findings.length ? 'No findings match these filters.' : 'No problems found.'}
            </p>
          ) : (
            <div className="csme-sec__table-wrap">
              <table className="csme-sec__table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Item</th>
                    <th>Field</th>
                    <th>Rule</th>
                    <th>Excerpt</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.slice(0, rows).map((f, i) => (
                    <tr key={`${f.collection}-${f.id}-${f.field}-${f.rule}-${i}`}>
                      <td>
                        <span className={`csme-sev csme-sev--${f.severity}`}>{SEVERITY_LABEL[f.severity]}</span>
                      </td>
                      <td>
                        <a href={f.adminUrl} target="_blank" rel="noopener noreferrer" className="csme-sec__item">
                          {f.title || `#${f.id}`}
                        </a>
                        <span className="csme-sec__meta">
                          {f.collection}
                          {f.id !== '' ? ` #${f.id}` : ''}
                        </span>
                      </td>
                      <td>
                        <code>{f.field}</code>
                      </td>
                      <td title={RULES[f.rule]?.description}>
                        {RULES[f.rule]?.title || f.rule}
                        {f.count > 1 ? <span className="csme-sec__meta">×{f.count}</span> : null}
                      </td>
                      <td className="csme-sec__excerpt">
                        {/* Rendered as text: React escapes it, so malicious markup can't run here. */}
                        <code>{f.excerpt}</code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filtered.length > rows && (
                <button type="button" className="csme-btn csme-btn--outline csme-sec__more" onClick={() => setRows((r) => r + ROWS_STEP)}>
                  Show more ({(filtered.length - rows).toLocaleString('en-CA')} left)
                </button>
              )}
            </div>
          )}
        </>
      )}

      <p className="csme-sec__footnote">
        Fix a finding by opening the item and editing it (for imported articles, edit the &quot;Original WordPress
        HTML&quot; or untick it and use the editor). Saving runs the HTML cleaner again. Users and redirects are under{' '}
        <a href={`${adminRoute}/collections/users`}>Users</a> and <a href={`${adminRoute}/collections/redirects`}>Redirects</a>;
        failed logins in the <a href={`${adminRoute}/collections/audit-logs`}>Activity log</a>. See SECURITY.md for details.
      </p>
    </section>
  )
}

export default SecurityScanner
