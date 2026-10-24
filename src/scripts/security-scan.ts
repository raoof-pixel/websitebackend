/**
 * Command-line security scan (READ-ONLY). Same checks as Admin → Security scan
 * (src/security/scan.ts), run directly against the database in DATABASE_URL.
 *
 *   pnpm security:scan                          # everything, report in ci-output/
 *   pnpm security:scan --only=posts,users       # some targets
 *   pnpm security:scan --fail-on=critical       # exit 1 if anything critical is found
 *   pnpm security:scan --out=reports            # other output folder
 *
 * Writes <out>/security-scan.json (all findings) and <out>/security-scan.md (summary).
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { getPayload } from 'payload'

import config from '../payload.config'
import { RULES, SEVERITIES, type Severity } from '../security/rules'
import { type Finding, SCAN_TARGETS, type ScanTarget, isScanTarget, scanTarget, summarize } from '../security/scan'

const arg = (name: string): string | undefined => {
  const hit = process.argv.find((a) => a === `--${name}` || a.startsWith(`--${name}=`))
  if (!hit) return undefined
  return hit.includes('=') ? hit.slice(hit.indexOf('=') + 1) : 'true'
}

const only = (arg('only') || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
const targets: ScanTarget[] = only.length
  ? only.filter(isScanTarget)
  : SCAN_TARGETS.map((t) => t.target)
const failOn = arg('fail-on') as Severity | undefined
const outDir = path.resolve(arg('out') || 'ci-output')

try {
  const payload = await getPayload({ config })
  const findings: Finding[] = []
  const scanned: Record<string, number> = {}
  const started = Date.now()

  for (const target of targets) {
    let page = 1
    let totalPages = 1
    do {
      const r = await scanTarget(payload, target, page)
      totalPages = r.totalPages
      scanned[target] = (scanned[target] || 0) + r.scanned
      findings.push(...r.findings)
      process.stdout.write(`\r${target}: page ${page}/${totalPages}, ${findings.length} findings so far   `)
      page++
    } while (page <= totalPages)
    process.stdout.write('\n')
  }

  const summary = summarize(findings)
  mkdirSync(outDir, { recursive: true })
  writeFileSync(
    path.join(outDir, 'security-scan.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), durationMs: Date.now() - started, scanned, summary, findings }, null, 2),
  )

  const lines = [
    '# Security scan',
    '',
    `Scanned: ${Object.entries(scanned).map(([t, n]) => `${t} ${n}`).join(', ')}`,
    '',
    `| Severity | Findings |`,
    `| --- | ---: |`,
    ...SEVERITIES.map((s) => `| ${s} | ${summary.bySeverity[s]} |`),
    '',
    '## By rule',
    '',
    ...Object.entries(summary.byRule)
      .sort((a, b) => (b[1] || 0) - (a[1] || 0))
      .map(([rule, n]) => `- **${RULES[rule as keyof typeof RULES]?.title || rule}** (\`${rule}\`): ${n}`),
    '',
    '## Most severe (first 50)',
    '',
    ...findings
      .filter((f) => f.severity === 'critical' || f.severity === 'high')
      .slice(0, 50)
      .map((f) => `- ${f.severity.toUpperCase()} ${f.collection} #${f.id} "${f.title}" ${f.field}: ${f.rule} — \`${f.excerpt.replace(/`/g, "'")}\``),
    '',
  ]
  writeFileSync(path.join(outDir, 'security-scan.md'), lines.join('\n'))
  console.log(lines.slice(0, 10 + SEVERITIES.length).join('\n'))

  let exitCode = 0
  if (failOn && SEVERITIES.includes(failOn)) {
    const limit = SEVERITIES.indexOf(failOn)
    if (findings.some((f) => SEVERITIES.indexOf(f.severity) <= limit)) exitCode = 1
  }
  process.exit(exitCode)
} catch (err) {
  console.error(err)
  process.exit(1)
}
