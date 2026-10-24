// Unit tests for the security scanner rules (src/security/rules.ts). No database needed.
// Run: pnpm test:security   (= node --import tsx --test tests/security-rules.test.mjs)
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  RULES,
  SEVERITIES,
  clip,
  hostOf,
  isHiddenStyle,
  isSuspiciousEmail,
  lexicalToScanHtml,
  scanFile,
  scanHtml,
  scanName,
  scanSocialLink,
  scanText,
  scanUrl,
} from '../src/security/rules.ts'

const rules = (hits) => hits.map((h) => h.rule)
const hit = (hits, rule) => hits.find((h) => h.rule === rule)

test('every rule is documented with a valid severity', () => {
  for (const [id, info] of Object.entries(RULES)) {
    assert.equal(info.id, id)
    assert.ok(SEVERITIES.includes(info.severity), id)
    assert.ok(info.title && info.description, id)
  }
})

test('script tags are critical and name the host they load', () => {
  const h = hit(scanHtml('<p>Hi</p><script src="https://evil.ru/x.js"></script>'), 'script-tag')
  assert.equal(h?.severity, 'critical')
  assert.match(h.excerpt, /evil\.ru/)
  // Even when a "<" inside an attribute confuses the tag parser.
  assert.ok(rules(scanHtml('<img alt="<" src=x onerror=alert(1)><script>alert(1)</script>')).includes('script-tag'))
})

test('event handlers and javascript:/vbscript:/data: URLs are found, also when entity-encoded', () => {
  const r = scanHtml('<img src="x.jpg" onerror="alert(1)"><a href="java&#115;cript:alert(1)">x</a>')
  assert.ok(rules(r).includes('event-handler'))
  assert.equal(hit(r, 'dangerous-url')?.severity, 'critical')
  assert.ok(rules(scanHtml('<a href="vbscript:msgbox(1)">x</a>')).includes('dangerous-url'))
  assert.equal(hit(scanHtml('<iframe src="data:text/html;base64,PHNjcmlwdD4="></iframe>'), 'dangerous-url')?.severity, 'high')
  assert.deepEqual(rules(scanHtml('<img src="data:image/png;base64,iVBORw0KGgo=">')), [])
})

test('iframes are only trusted from the sanitizer allow-list', () => {
  const r = scanHtml('<iframe src="https://evil.example.com/x"></iframe><iframe src="https://www.youtube.com/embed/abc"></iframe>')
  const h = hit(r, 'untrusted-embed')
  assert.equal(h?.count, 1)
  assert.match(h.excerpt, /evil\.example\.com/)
  assert.ok(rules(scanHtml('<object data="https://x.top/a.swf"></object>')).includes('untrusted-embed'))
  assert.deepEqual(rules(scanHtml('<iframe src="https://player.vimeo.com/video/1"></iframe>')), [])
})

test('hidden content with links is high, without links low', () => {
  assert.equal(hit(scanHtml('<div style="display:none"><a href="https://spam.example">casino</a></div>'), 'hidden-link')?.severity, 'high')
  assert.ok(rules(scanHtml('<span style="font-size:0px"><a href="https://x.com">x</a></span>')).includes('hidden-link'))
  assert.ok(rules(scanHtml('<div style="position:absolute;left:-9999px">best online casino bonus here</div>')).includes('hidden-link'))
  assert.deepEqual(rules(scanHtml('<div style="display:none">Some accordion text that is long enough</div>')), ['hidden-content'])
  assert.equal(isHiddenStyle('font-size: 0.8em'), false)
  assert.equal(isHiddenStyle('height:0;overflow:hidden'), true)
  assert.equal(isHiddenStyle('opacity: 0.5'), false)
})

test('spam keywords count in links and clusters, not single mentions', () => {
  const link = scanHtml('<p>Read <a href="https://cheap-viagra.xyz/buy">buy viagra online</a></p>')
  assert.ok(rules(link).includes('spam-link'))
  assert.ok(rules(link).includes('suspicious-domain'))
  assert.ok(rules(scanHtml('<p>payday loans and free spins and replica watches</p>')).includes('spam-keywords'))
  assert.deepEqual(rules(scanHtml('<p>Small business loans are growing. Pharmacy chains report record sales. Crypto adoption rises.</p>')), [])
  assert.deepEqual(rules(scanHtml('<p>Ontario regulates the online casino market.</p>')), [])
})

test('obfuscation and redirects', () => {
  const r = scanHtml('<p>eval(atob("ZG9jdW1lbnQ="))</p> window.location = "http://x.top"')
  assert.ok(rules(r).includes('obfuscated-js'))
  assert.equal(hit(r, 'js-redirect')?.severity, 'critical')
  assert.ok(rules(scanHtml('<meta http-equiv="refresh" content="0;url=https://spam.top">')).includes('meta-refresh'))
  assert.ok(rules(scanHtml('x = "\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x65"')).includes('obfuscated-js'))
  assert.ok(rules(scanHtml('<p>' + '&#104;'.repeat(25) + '</p>')).includes('encoded-text'))
})

test('long base64 payloads are reported, inline images are not', () => {
  const payload = Buffer.from('<script>document.write("hello world payload")</script>'.repeat(6)).toString('base64')
  assert.equal(hit(scanHtml(`x ${payload}`), 'base64-blob')?.severity, 'high')
  const img = 'iVBORw0KGgo1AAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ'.repeat(10)
  assert.deepEqual(rules(scanHtml(`<img src="data:image/png;base64,${img}">`)), [])
})

test('IP links, shorteners, cloaked links and link floods', () => {
  const r = scanHtml('<a href="http://185.12.33.4/x">click</a><a href="https://bit.ly/abc">x</a><a href="https://evil.top/x">www.rbc.com</a>')
  assert.ok(rules(r).includes('ip-address-link'))
  assert.ok(rules(r).includes('url-shortener'))
  assert.ok(rules(r).includes('cloaked-link'))
  // Press-release tracking links are not "cloaked".
  assert.deepEqual(rules(scanHtml('<a href="https://c212.net/c/link/?u=x">www.company.com</a>')), [])
  const many = Array.from({ length: 45 }, (_, i) => `<a href="https://site${i}.com/">s</a>`).join('')
  assert.ok(rules(scanHtml(many)).includes('external-link-flood'))
  const own = Array.from({ length: 45 }, (_, i) => `<a href="https://www.canadiansme.ca/p${i}/">s</a>`).join('')
  assert.deepEqual(rules(scanHtml(own)), [])
})

test('rich-text (Lexical) content: URLs kept raw, typed text escaped', () => {
  const lex = {
    root: {
      type: 'root',
      children: [
        {
          type: 'paragraph',
          children: [
            { type: 'text', text: 'I write about <script> tags' },
            { type: 'link', fields: { url: 'javascript:alert(1)', linkType: 'custom' }, children: [{ type: 'text', text: 'click' }] },
          ],
        },
        { type: 'block', fields: { blockType: 'html', html: '<iframe src="https://bad.cn/"></iframe>' } },
        { type: 'block', fields: { blockType: 'embed', url: 'https://bit.ly/x' } },
      ],
    },
  }
  const r = rules(scanHtml(lexicalToScanHtml(lex)))
  assert.ok(r.includes('dangerous-url'))
  assert.ok(r.includes('untrusted-embed'))
  assert.ok(r.includes('url-shortener'))
  assert.ok(!r.includes('script-tag'), 'text mentioning <script> must not count as a script')
  assert.equal(lexicalToScanHtml(null), '')
})

test('names, text fields and URLs', () => {
  assert.ok(rules(scanName('Best Online Casino Bonus')).includes('spam-name'))
  assert.deepEqual(rules(scanName('Interviews')), [])
  assert.deepEqual(rules(scanName('Small Business Loans')), [])
  assert.ok(rules(scanText('Great article! payday loans https://loans.example.top/')).includes('spam-link'))
  assert.ok(rules(scanText('<script>alert(1)</script>')).includes('script-tag'))
  assert.ok(rules(scanUrl('http://example.com', { requireHttps: true })).includes('insecure-url'))
  assert.deepEqual(rules(scanUrl('https://www.bdc.ca/en')), [])
  assert.deepEqual(rules(scanUrl('/category/news/')), [])
  assert.equal(hostOf('//Evil.TOP/x'), 'evil.top')
  assert.equal(hostOf('/relative'), '')
})

test('uploaded files', () => {
  assert.ok(rules(scanFile({ filename: 'shell.php.jpg', mimeType: 'image/jpeg' })).includes('double-extension'))
  assert.equal(hit(scanFile({ filename: 'x.php', mimeType: 'application/x-php' }), 'dangerous-file')?.severity, 'critical')
  assert.ok(rules(scanFile({ filename: 'logo.svg', mimeType: 'image/svg+xml' })).includes('dangerous-file'))
  const r = rules(scanFile({ filename: 'x.jpg', mimeType: 'text/html', wpUrl: 'https://evil.ru/wp-content/uploads/x.jpg.php' }))
  assert.ok(r.includes('mime-mismatch') && r.includes('offsite-media') && r.includes('dangerous-file'))
  assert.deepEqual(rules(scanFile({ filename: 'photo.jpg', mimeType: 'image/jpeg', wpUrl: 'https://i0.wp.com/canadiansme.ca/wp-content/uploads/photo.jpg' })), [])
  assert.deepEqual(rules(scanFile({ filename: 'report.2024.pdf', mimeType: 'application/pdf', wpUrl: 'https://canadiansme.ca/wp-content/uploads/report.2024.pdf' })), [])
})

test('emails and social links', () => {
  assert.equal(isSuspiciousEmail('a@mailinator.com'), true)
  assert.equal(isSuspiciousEmail('a@x.ru'), true)
  assert.equal(isSuspiciousEmail('raoof@canadiansme.ca'), false)
  assert.ok(rules(scanSocialLink('facebook', 'https://facebook.evil.top/canadiansme')).includes('social-link-mismatch'))
  assert.deepEqual(rules(scanSocialLink('linkedin', 'https://www.linkedin.com/company/canadiansme-business-magazine')), [])
})

test('excerpts are at most 160 characters', () => {
  assert.ok(clip('x'.repeat(500)).length <= 160)
  for (const h of scanHtml(`<script>${'a'.repeat(5000)}</script><a href="https://x.top/${'b'.repeat(400)}">y</a>`)) {
    assert.ok(h.excerpt.length <= 160, `${h.rule}: ${h.excerpt.length}`)
  }
})

test('malformed markup cannot make the scan slow', () => {
  const t = Date.now()
  scanHtml('<a '.repeat(200_000))
  scanHtml('<'.repeat(300_000))
  scanHtml('<p>Some <a href="https://example.com/a">text</a> and words. </p>'.repeat(10_000))
  assert.ok(Date.now() - t < 5000, `took ${Date.now() - t} ms`)
})
