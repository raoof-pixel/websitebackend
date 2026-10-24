// Turns `pnpm audit --prod --json` output into a readable GitHub job summary and annotations.
// Usage: pnpm audit --prod --json > audit.json; node .github/scripts/audit-summary.mjs audit.json [--fail-on=high]
// Exit code is 0 unless --fail-on=high|critical is given and such advisories exist.
import { appendFileSync, readFileSync } from 'node:fs'

const file = process.argv[2] || 'audit.json'
const failOn = (process.argv.find((a) => a.startsWith('--fail-on=')) || '').split('=')[1] || ''
let data = {}
try {
  data = JSON.parse(readFileSync(file, 'utf8') || '{}')
} catch (err) {
  console.log(`::warning::Could not read pnpm audit output (${err.message})`)
}
const counts = { critical: 0, high: 0, moderate: 0, low: 0, info: 0, ...(data.metadata?.vulnerabilities || {}) }
const advisories = Object.values(data.advisories || {})
const rank = { critical: 4, high: 3, moderate: 2, low: 1, info: 0 }
advisories.sort((a, b) => (rank[b.severity] || 0) - (rank[a.severity] || 0))

const lines = [
  '## Dependency audit (`pnpm audit --prod`)',
  '',
  '| Critical | High | Moderate | Low |',
  '| ---: | ---: | ---: | ---: |',
  `| ${counts.critical} | ${counts.high} | ${counts.moderate} | ${counts.low} |`,
  '',
]
const serious = advisories.filter((a) => a.severity === 'critical' || a.severity === 'high')
if (serious.length) {
  lines.push('| Severity | Package | Problem | Fixed in |', '| --- | --- | --- | --- |')
  for (const a of serious.slice(0, 50)) {
    const title = String(a.title || '').replace(/\|/g, '/')
    lines.push(`| **${a.severity}** | \`${a.module_name}\` | [${title}](${a.url}) | ${a.patched_versions || '-'} |`)
    console.log(`::${a.severity === 'critical' ? 'error' : 'warning'} title=${a.severity} vulnerability in ${a.module_name}::${title} (fixed in ${a.patched_versions || 'n/a'}) ${a.url}`)
  }
  lines.push('', 'Fix: `pnpm up <package>` (or add a `pnpm.overrides` entry in package.json), then re-run CI.')
} else {
  lines.push('No high or critical advisories.')
}
lines.push('')

const out = lines.join('\n')
console.log(out)
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${out}\n`)

const limit = rank[failOn === 'high' ? 'high' : failOn === 'critical' ? 'critical' : ''] ?? 99
process.exit(advisories.some((a) => (rank[a.severity] || 0) >= limit) ? 1 : 0)
