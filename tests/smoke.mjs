// End-to-end smoke + security tests against a running CMS (production build).
// Usage: BASE_URL=http://localhost:3000 node tests/smoke.mjs
// Writes a report to ci-output/smoke-report.md and exits non-zero on any failure.
import { mkdirSync, writeFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'

const BASE = (process.env.BASE_URL || 'http://localhost:3000').replace(/\/$/, '')
const results = []
const record = (name, ok, detail = '') => {
  results.push({ name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  — ${detail}` : ''}`)
}
const test = async (name, fn) => {
  try {
    const detail = await fn()
    record(name, true, typeof detail === 'string' ? detail : '')
  } catch (err) {
    record(name, false, err?.message || String(err))
  }
}
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg)
}

const cookieFrom = (res) => {
  const all = res.headers.getSetCookie?.() || []
  return all.map((c) => c.split(';')[0]).join('; ')
}
const api = async (path, { method = 'GET', body, cookie, apiKey, headers = {}, raw } = {}) => {
  const h = { ...headers }
  if (cookie) h.cookie = cookie
  if (apiKey) h.authorization = `users API-Key ${apiKey}`
  if (body && !raw) h['content-type'] = 'application/json'
  // Same-origin requests, like the admin panel makes them (needed for CSRF checks with cookies).
  h.origin = BASE
  const res = await fetch(`${BASE}${path}`, { method, headers: h, body: raw ? body : body ? JSON.stringify(body) : undefined })
  let json = null
  const text = await res.text()
  try {
    json = JSON.parse(text)
  } catch {
    json = { text: text.slice(0, 300) }
  }
  return { res, status: res.status, json }
}

const ADMIN = { email: 'admin@example.com', password: 'Str0ng!Owner#Pass2026', name: 'Test Admin' }
const AUTHOR_A = { email: 'author.a@example.com', password: 'Auth0r!A#Secure2026', name: 'Author A', roles: ['author'] }
const AUTHOR_B = { email: 'author.b@example.com', password: 'Auth0r!B#Secure2026', name: 'Author B', roles: ['author'] }
const BOT = { email: 'bot@example.com', password: 'B0t!Automation#2026x', name: 'Newswire bot', roles: ['automation'] }

let adminCookie = ''
let ids = {}

await test('Health endpoint responds', async () => {
  const { status, json } = await api('/api/health')
  assert(status === 200 && json.ok, `status ${status} ${JSON.stringify(json)}`)
})

await test('Security headers are sent', async () => {
  const res = await fetch(`${BASE}/admin`, { redirect: 'manual' })
  const need = ['x-frame-options', 'x-content-type-options', 'strict-transport-security', 'content-security-policy', 'referrer-policy', 'x-robots-tag']
  const missing = need.filter((h) => !res.headers.get(h))
  assert(missing.length === 0, `missing: ${missing.join(', ')}`)
  assert(!res.headers.get('x-powered-by'), 'x-powered-by header is exposed')
})

await test('Weak password is rejected for the first admin', async () => {
  const { status } = await api('/api/users/first-register', { method: 'POST', body: { ...ADMIN, password: 'password123' } })
  assert(status >= 400, `expected rejection, got ${status}`)
})

await test('First admin can register with a strong password', async () => {
  const { status, json } = await api('/api/users/first-register', { method: 'POST', body: ADMIN })
  assert(status === 200 || status === 201, `status ${status} ${JSON.stringify(json).slice(0, 200)}`)
})

await test('Admin can log in (token only in HttpOnly cookie)', async () => {
  const { res, status, json } = await api('/api/users/login', { method: 'POST', body: { email: ADMIN.email, password: ADMIN.password } })
  assert(status === 200, `status ${status}`)
  adminCookie = cookieFrom(res)
  assert(adminCookie.includes('payload-token'), 'no payload-token cookie')
  const raw = (res.headers.getSetCookie?.() || []).join(' ').toLowerCase()
  assert(raw.includes('httponly'), 'cookie is not HttpOnly')
  assert(!json.token, 'token was returned in the response body')
  assert((json.user?.roles || []).includes('admin'), 'first user is not admin')
})

await test('Public cannot register new users', async () => {
  const { status } = await api('/api/users', { method: 'POST', body: { ...AUTHOR_A, email: 'intruder@example.com', roles: ['admin'] } })
  assert(status === 403 || status === 401, `expected 401/403, got ${status}`)
})

await test('Admin creates authors and an automation user', async () => {
  for (const u of [AUTHOR_A, AUTHOR_B, BOT]) {
    const { status, json } = await api('/api/users', { method: 'POST', body: u, cookie: adminCookie })
    assert(status === 201 || status === 200, `${u.email}: ${status} ${JSON.stringify(json).slice(0, 200)}`)
    ids[u.email] = json.doc.id
  }
})

await test('Weak password is rejected when an admin creates a user', async () => {
  const { status } = await api('/api/users', { method: 'POST', body: { email: 'weak@example.com', password: 'Short1!', name: 'Weak', roles: ['author'] }, cookie: adminCookie })
  assert(status === 400, `expected 400, got ${status}`)
})

let authorACookie = ''
await test('Author cannot promote themselves to admin', async () => {
  const login = await api('/api/users/login', { method: 'POST', body: { email: AUTHOR_A.email, password: AUTHOR_A.password } })
  assert(login.status === 200, `login ${login.status}`)
  authorACookie = cookieFrom(login.res)
  await api(`/api/users/${ids[AUTHOR_A.email]}`, { method: 'PATCH', body: { roles: ['admin'] }, cookie: authorACookie })
  const me = await api(`/api/users/${ids[AUTHOR_A.email]}`, { cookie: adminCookie })
  assert(JSON.stringify(me.json.roles) === JSON.stringify(['author']), `roles became ${JSON.stringify(me.json.roles)}`)
})

await test('Account locks after 5 wrong passwords', async () => {
  for (let i = 0; i < 5; i++) {
    await api('/api/users/login', { method: 'POST', body: { email: AUTHOR_B.email, password: 'wrong-password-123!A' } })
  }
  const { status } = await api('/api/users/login', { method: 'POST', body: { email: AUTHOR_B.email, password: AUTHOR_B.password } })
  assert(status !== 200, 'correct password still worked after 5 failures (no lockout)')
  return `login with correct password after lockout -> ${status}`
})

await test('Automation user cannot log in with a password', async () => {
  const { status } = await api('/api/users/login', { method: 'POST', body: { email: BOT.email, password: BOT.password } })
  assert(status === 403 || status === 401, `expected 401/403, got ${status}`)
})

const botKey = randomUUID()
await test('Admin enables an API key for the automation user', async () => {
  const { status, json } = await api(`/api/users/${ids[BOT.email]}`, { method: 'PATCH', body: { enableAPIKey: true, apiKey: botKey }, cookie: adminCookie })
  assert(status === 200, `status ${status} ${JSON.stringify(json).slice(0, 200)}`)
})

await test('Admin creates a category', async () => {
  const { status, json } = await api('/api/categories', { method: 'POST', body: { title: 'Latest News', slug: 'latest-news' }, cookie: adminCookie })
  assert(status === 201, `status ${status} ${JSON.stringify(json).slice(0, 200)}`)
  ids.category = json.doc.id
})

const evil = [
  '<p>Hello <strong>world</strong></p>',
  '<script>alert(1)</script>',
  '<img src="x.jpg" onerror="alert(2)">',
  '<a href="javascript:alert(3)">bad link</a>',
  '<a href="https://example.com" target="_blank">ok link</a>',
  '<iframe src="https://evil.example.com/x"></iframe>',
  '<iframe src="https://www.youtube.com/embed/abc"></iframe>',
  '<div style="display:none"><a href="https://spam.example">casino</a></div>',
].join('\n')

await test('Admin publishes an article; injected HTML is cleaned on save', async () => {
  const { status, json } = await api('/api/posts', {
    method: 'POST',
    cookie: adminCookie,
    body: {
      title: 'Security Test Article',
      excerpt: 'Testing',
      categories: [ids.category],
      legacyHtml: evil,
      useLegacyHtml: true,
      _status: 'published',
    },
  })
  assert(status === 201, `status ${status} ${JSON.stringify(json).slice(0, 300)}`)
  ids.post = json.doc.id
  const html = json.doc.legacyHtml || ''
  assert(!/<script/i.test(html), 'script tag survived')
  assert(!/onerror/i.test(html), 'onerror handler survived')
  assert(!/javascript:/i.test(html), 'javascript: link survived')
  assert(!/evil\.example/i.test(html), 'untrusted iframe survived')
  assert(/youtube\.com\/embed/i.test(html), 'trusted YouTube iframe was removed')
  assert(/noopener/i.test(html), 'target=_blank link missing rel=noopener')
  assert(!/style=/i.test(html), 'inline style survived')
  assert(json.doc.slug === 'security-test-article', `slug is ${json.doc.slug}`)
  assert(json.doc.publishedAt, 'publishedAt not set')
})

await test('Public can read published articles but not who created them', async () => {
  const { status, json } = await api(`/api/posts/${ids.post}`)
  assert(status === 200, `status ${status}`)
  assert(json.createdBy === undefined, 'createdBy is exposed publicly')
})

await test('Drafts are hidden from the public', async () => {
  const d = await api('/api/posts', { method: 'POST', cookie: adminCookie, body: { title: 'Secret Draft', _status: 'draft' } })
  assert(d.status === 201, `create ${d.status}`)
  ids.draft = d.json.doc.id
  const pub = await api(`/api/posts?where[slug][equals]=secret-draft`)
  assert(pub.json.totalDocs === 0, 'draft visible to public')
})

await test('/api/resolve finds an article by its WordPress-style URL', async () => {
  const { status, json } = await api('/api/resolve?path=/security-test-article/')
  assert(status === 200 && json.type === 'post', `got ${status} ${JSON.stringify(json).slice(0, 200)}`)
  const cat = await api('/api/resolve?path=/category/latest-news/')
  assert(cat.json.type === 'category', `category resolve: ${JSON.stringify(cat.json).slice(0, 200)}`)
  const nf = await api('/api/resolve?path=/no-such-page/')
  assert(nf.status === 404, `missing page returned ${nf.status}`)
})

await test('Automation API key creates articles as drafts only', async () => {
  const { status, json } = await api('/api/posts', { method: 'POST', apiKey: botKey, body: { title: 'Newswire Bot Article', _status: 'published' } })
  assert(status === 201, `status ${status} ${JSON.stringify(json).slice(0, 200)}`)
  ids.botPost = json.doc.id
  assert(json.doc._status === 'draft', `bot article status is ${json.doc._status}`)
})

await test('Automation API key cannot delete articles', async () => {
  const { status } = await api(`/api/posts/${ids.post}`, { method: 'DELETE', apiKey: botKey })
  assert(status === 403 || status === 401, `expected 403, got ${status}`)
  const still = await api(`/api/posts/${ids.post}`)
  assert(still.status === 200, 'article was deleted')
})

await test('Author cannot edit or delete someone else’s article', async () => {
  const upd = await api(`/api/posts/${ids.post}`, { method: 'PATCH', cookie: authorACookie, body: { title: 'Hacked' } })
  assert(upd.status === 403 || upd.status === 404, `update returned ${upd.status}`)
  const del = await api(`/api/posts/${ids.post}`, { method: 'DELETE', cookie: authorACookie })
  assert(del.status === 403 || del.status === 404, `delete returned ${del.status}`)
})

await test('Author can create and edit their own article', async () => {
  const c = await api('/api/posts', { method: 'POST', cookie: authorACookie, body: { title: 'Author Own Article', _status: 'draft' } })
  assert(c.status === 201, `create ${c.status} ${JSON.stringify(c.json).slice(0, 200)}`)
  const u = await api(`/api/posts/${c.json.doc.id}`, { method: 'PATCH', cookie: authorACookie, body: { title: 'Author Own Article Edited' } })
  assert(u.status === 200, `update ${u.status}`)
})

const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64')
await test('PNG image upload works', async () => {
  const fd = new FormData()
  fd.append('file', new Blob([png], { type: 'image/png' }), 'pixel.png')
  fd.append('_payload', JSON.stringify({ alt: 'test pixel' }))
  const { status, json } = await api('/api/media', { method: 'POST', cookie: adminCookie, body: fd, raw: true })
  assert(status === 201, `status ${status} ${JSON.stringify(json).slice(0, 300)}`)
})

await test('SVG upload is blocked (can carry scripts)', async () => {
  const svg = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
  const fd = new FormData()
  fd.append('file', new Blob([svg], { type: 'image/svg+xml' }), 'evil.svg')
  fd.append('_payload', JSON.stringify({ alt: 'evil' }))
  const { status } = await api('/api/media', { method: 'POST', cookie: adminCookie, body: fd, raw: true })
  assert(status >= 400, `SVG accepted with status ${status}`)
})

await test('Disguised script upload is blocked', async () => {
  const fd = new FormData()
  fd.append('file', new Blob(['<?php system($_GET["c"]); ?>'], { type: 'image/png' }), 'shell.php.png')
  fd.append('_payload', JSON.stringify({ alt: 'shell' }))
  const { status } = await api('/api/media', { method: 'POST', cookie: adminCookie, body: fd, raw: true })
  assert(status >= 400, `fake image accepted with status ${status}`)
})

await test('Activity log records actions and is admin-only', async () => {
  const pub = await api('/api/audit-logs')
  assert(pub.status === 403 || pub.status === 401, `public read returned ${pub.status}`)
  const a = await api('/api/audit-logs?limit=100', { cookie: adminCookie })
  assert(a.status === 200, `admin read ${a.status}`)
  const actions = new Set(a.json.docs.map((d) => d.action))
  for (const need of ['login', 'login-failed', 'publish', 'create']) assert(actions.has(need), `no "${need}" entries (have: ${[...actions].join(', ')})`)
  return `${a.json.totalDocs} entries, actions: ${[...actions].join(', ')}`
})

await test('Activity log cannot be deleted or edited, even by an admin', async () => {
  const a = await api('/api/audit-logs?limit=1', { cookie: adminCookie })
  const id = a.json.docs[0]?.id
  const del = await api(`/api/audit-logs/${id}`, { method: 'DELETE', cookie: adminCookie })
  assert(del.status === 403, `delete returned ${del.status}`)
  const upd = await api(`/api/audit-logs/${id}`, { method: 'PATCH', cookie: adminCookie, body: { summary: 'x' } })
  assert(upd.status === 403, `update returned ${upd.status}`)
})

await test('GraphQL introspection is disabled in production', async () => {
  const { json } = await api('/api/graphql', { method: 'POST', body: { query: '{ __schema { types { name } } }' } })
  assert(!json?.data?.__schema, 'schema introspection returned data')
})

await test('Requests from other websites are refused CORS access', async () => {
  const res = await fetch(`${BASE}/api/posts`, { headers: { origin: 'https://evil.example.com' } })
  const allow = res.headers.get('access-control-allow-origin')
  assert(allow !== 'https://evil.example.com' && allow !== '*', `CORS allowed: ${allow}`)
})

await test('Site settings are readable and admin-only to change', async () => {
  const r = await api('/api/globals/site-settings')
  assert(r.status === 200, `read ${r.status}`)
  const w = await api('/api/globals/site-settings', { method: 'POST', cookie: authorACookie, body: { siteName: 'Hacked' } })
  assert(w.status === 403, `author write returned ${w.status}`)
})

await test('WordPress import endpoint is admin-only', async () => {
  const pub = await api('/api/wp-import', { method: 'POST', body: { step: 'authors' } })
  assert(pub.status === 403 || pub.status === 401, `public got ${pub.status}`)
  const au = await api('/api/wp-import', { method: 'POST', cookie: authorACookie, body: { step: 'authors' } })
  assert(au.status === 403 || au.status === 401, `author got ${au.status}`)
  const bot = await api('/api/wp-import', { method: 'POST', apiKey: botKey, body: { step: 'authors' } })
  assert(bot.status === 403 || bot.status === 401, `automation key got ${bot.status}`)
})

await test('Admin can run an import step from inside the CMS', async () => {
  const { status, json } = await api('/api/wp-import', { method: 'POST', cookie: adminCookie, body: { step: 'authors' } })
  assert(status === 200, `status ${status} ${JSON.stringify(json).slice(0, 300)}`)
  assert((json.counts?.authors || 0) > 400, `authors imported: ${json.counts?.authors}`)
  return `${json.counts.authors} authors`
})

// ---------- report ----------
const failed = results.filter((r) => !r.ok)
const lines = [
  `# Smoke & security test report`,
  ``,
  `${results.length - failed.length}/${results.length} passed`,
  ``,
  ...results.map((r) => `- ${r.ok ? '✅' : '❌'} ${r.name}${r.detail ? ` — ${r.detail}` : ''}`),
  ``,
]
mkdirSync('ci-output', { recursive: true })
writeFileSync('ci-output/smoke-report.md', lines.join('\n'))
console.log(`\n${results.length - failed.length}/${results.length} passed`)
process.exit(failed.length ? 1 : 0)
