/**
 * Security scanner rules: pure, dependency-free functions that look at a piece of content
 * (HTML, plain text, a URL, a file name) and report what looks like the leftovers of a hack.
 *
 * Why: the old WordPress site was hacked several times. Typical WordPress infections are
 *   - injected <script> tags, inline event handlers (onload=...) and javascript: links,
 *   - iframes / objects loading pages from attacker-controlled sites,
 *   - hidden spam links (display:none, font-size:0, positioned off-screen) for SEO spam,
 *   - pharma / casino / payday-loan / adult / crypto-scam / essay / replica keywords and links,
 *   - obfuscated JavaScript (eval, atob, String.fromCharCode, document.write, unescape, \x41...),
 *   - redirects to spam sites (meta refresh, window.location = ...),
 *   - links "cloaked" behind innocent text, pointing at throw-away TLDs, shorteners or raw IPs,
 *   - rogue admin accounts and uploaded web shells (shell.php, x.jpg.php, .svg with scripts).
 * About 8,800 articles were imported from that database, so their `legacyHtml` may still carry
 * some of it. Content is cleaned by sanitize-html when it is saved, but anything imported before
 * the cleaner existed (or written straight to the database) is not, and spam links survive any
 * HTML cleaner because they are ordinary <a href> links. This module finds them.
 *
 * Everything here is deterministic and side-effect free so it can be unit-tested
 * (tests/security-rules.test.mjs) and reused by the API endpoint, the admin view (rule
 * descriptions) and the CLI script. It never changes content: it only reports.
 *
 * Accuracy notes (keep false positives low):
 *   - Spam keywords are only reported when they appear INSIDE a link (text or URL), in a
 *     cluster (several different spam terms in one field), or in a short name/title field.
 *     A business magazine legitimately writes about "loans", "crypto" or "pharmacy", so the
 *     dictionary only contains phrases that are almost never legitimate ("payday loans",
 *     "buy viagra", "replica watches", "slot gacor", ...).
 *   - Hidden-content CSS alone is common in old page-builder markup, so it is only "low"
 *     unless the hidden part contains a link or spam words ("high").
 *   - Text typed into the rich-text editor is escaped before scanning, so an article that
 *     *mentions* "<script>" in a paragraph is not reported as a script tag.
 */
import { ALLOWED_IFRAME_HOSTS } from '../utilities/iframeHosts'

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

export type Severity = 'critical' | 'high' | 'medium' | 'low'

/** Most severe first. */
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }

export const compareSeverity = (a: Severity, b: Severity): number => SEVERITY_RANK[b] - SEVERITY_RANK[a]

export type RuleGroup = 'code' | 'links' | 'spam' | 'media' | 'users' | 'redirects' | 'settings'

export type RuleId =
  // injected code
  | 'script-tag'
  | 'event-handler'
  | 'dangerous-url'
  | 'untrusted-embed'
  | 'external-form'
  | 'style-or-base-tag'
  | 'obfuscated-js'
  | 'encoded-text'
  | 'base64-blob'
  | 'js-redirect'
  | 'meta-refresh'
  // links
  | 'hidden-link'
  | 'hidden-content'
  | 'suspicious-domain'
  | 'ip-address-link'
  | 'url-shortener'
  | 'cloaked-link'
  | 'external-link-flood'
  | 'canonical-hijack'
  | 'insecure-url'
  // spam
  | 'spam-link'
  | 'spam-keywords'
  | 'spam-name'
  // media
  | 'dangerous-file'
  | 'double-extension'
  | 'mime-mismatch'
  | 'offsite-media'
  // users
  | 'admin-account'
  | 'many-admins'
  | 'new-admin'
  | 'mixed-automation-role'
  | 'api-key-on-person'
  | 'never-logged-in'
  | 'account-locked'
  | 'failed-logins'
  | 'brute-force-ip'
  | 'suspicious-email'
  // redirects / settings
  | 'external-redirect'
  | 'suspicious-redirect'
  | 'spam-redirect-path'
  | 'social-link-mismatch'
  // the scanner itself
  | 'scan-error'

export type RuleInfo = {
  id: RuleId
  title: string
  /** Default severity; a few rules raise or lower it depending on what they find. */
  severity: Severity
  group: RuleGroup
  /** Plain-English explanation shown in the admin view and in SECURITY.md. */
  description: string
  /** What usually causes a harmless match, so editors know when to ignore it. */
  falsePositives?: string
}

/** One problem found in one field. `count` = how many times the same rule matched that field. */
export type RuleHit = {
  rule: RuleId
  severity: Severity
  excerpt: string
  count: number
}

export type ScanOptions = {
  /**
   * Hosts that belong to CanadianSME (links to them are "internal"). canadiansme.ca and its
   * sub-domains are always included.
   */
  ownHosts?: string[]
  /** Report more than this many external links in one field (default 40). */
  maxExternalLinks?: number
}

// ---------------------------------------------------------------------------------------------
// Rule catalogue (documentation; also used by the admin view)
// ---------------------------------------------------------------------------------------------

const r = (
  id: RuleId,
  group: RuleGroup,
  severity: Severity,
  title: string,
  description: string,
  falsePositives?: string,
): RuleInfo => ({ id, group, severity, title, description, falsePositives })

export const RULES: Record<RuleId, RuleInfo> = {
  'script-tag': r('script-tag', 'code', 'critical', 'Script tag',
    'A <script> tag inside content. The most common WordPress infection: it loads malware, pop-ups or crypto miners on every page view.',
    'Old embed codes (Twitter, Instagram, forms) pasted as HTML also contain scripts; replace them with an Embed block.'),
  'event-handler': r('event-handler', 'code', 'high', 'Inline event handler',
    'An HTML attribute like onload=, onerror= or onclick= that runs JavaScript. Used to hide scripts inside images and links.'),
  'dangerous-url': r('dangerous-url', 'code', 'critical', 'javascript: / data: / vbscript: link',
    'A link or source that runs code instead of opening a page (javascript:, vbscript:) or carries a whole page inside the URL (data:text/html).'),
  'untrusted-embed': r('untrusted-embed', 'code', 'high', 'Iframe or embed from an unknown site',
    'An <iframe>, <embed>, <object> or <frame> loading a site that is not on the trusted list (YouTube, Vimeo, Spotify, Google Maps, ...). Attackers use invisible iframes to load malware or ads.',
    'A legitimate widget from a site not yet on the list. If you trust it, ask a developer to add the host to utilities/iframeHosts.ts.'),
  'external-form': r('external-form', 'code', 'medium', 'Form in content',
    'A <form> inside an article, especially one that sends data to another site. Can be a phishing form that collects passwords or card numbers.',
    'Old Mailchimp/newsletter sign-up forms.'),
  'style-or-base-tag': r('style-or-base-tag', 'code', 'medium', '<style>, <base>, <link> or <meta> tag in content',
    'Tags that change how the whole page looks or where its links go. Hacks use <style> to hide spam and <base> to redirect every relative link.',
    'Page-builder leftovers with inline <style> blocks.'),
  'obfuscated-js': r('obfuscated-js', 'code', 'high', 'Obfuscated JavaScript',
    'Code patterns used to hide malware: eval(), atob(), String.fromCharCode(), document.write(), unescape(), new Function(), long \\x41\\x42... escape sequences or _0x1a2b style variable names.',
    'An article that teaches JavaScript and shows such code as text.'),
  'encoded-text': r('encoded-text', 'code', 'medium', 'Heavily encoded text',
    'Long runs of HTML entities (&#104;&#116;...) or percent-encoding (%68%74...). Spammers encode links and words so filters cannot read them.',
    'Very long non-English URLs.'),
  'base64-blob': r('base64-blob', 'code', 'medium', 'Long base64 string',
    'A very long block of base64 text (not an inline image). Often a packed script or a hidden payload. Reported as high when the decoded text looks like code or a link.'),
  'js-redirect': r('js-redirect', 'code', 'critical', 'JavaScript redirect',
    'Code that sends visitors to another site (window.location = ..., location.replace(...)). The classic "my site redirects to a spam page" hack.'),
  'meta-refresh': r('meta-refresh', 'code', 'critical', 'Meta refresh redirect',
    'A <meta http-equiv="refresh"> tag that redirects visitors to another page after a delay.'),

  'hidden-link': r('hidden-link', 'links', 'high', 'Hidden link or hidden spam',
    'Content hidden with CSS (display:none, visibility:hidden, font-size:0, opacity:0, positioned thousands of pixels off-screen, zero height with overflow hidden) that contains links or spam words. Visitors cannot see it but Google can: classic SEO spam injection.'),
  'hidden-content': r('hidden-content', 'links', 'low', 'Hidden content',
    'Text hidden with CSS but without links. Usually harmless page-builder markup, worth a look if the text is unrelated to the article.',
    'Accordions, tabs and "read more" sections from old page builders.'),
  'suspicious-domain': r('suspicious-domain', 'links', 'medium', 'Link to a suspicious domain',
    'A link to a top-level domain that is mostly used by spam and malware (.ru, .cn, .top, .xyz, .click, .loan, .work, .bid, .tk, ...).',
    'A genuine business that happens to use one of these endings.'),
  'ip-address-link': r('ip-address-link', 'links', 'high', 'Link to a raw IP address',
    'A link to http://123.45.67.89/... instead of a domain name. Real businesses almost never do this; malware servers often do.'),
  'url-shortener': r('url-shortener', 'links', 'low', 'Shortened link',
    'A bit.ly / tinyurl / cutt.ly style link. It hides where the link really goes, and the target can be changed later by whoever owns it.',
    'Links copied from social media posts or press releases. Replace them with the real address when you can.'),
  'cloaked-link': r('cloaked-link', 'links', 'low', 'Link text shows a different site',
    'The link text looks like one web address (e.g. "www.bank.ca") but the link goes to a different domain. Common in phishing and spam.',
    'Click-tracking links in press releases (newswire tracking hosts are ignored).'),
  'external-link-flood': r('external-link-flood', 'links', 'medium', 'Unusually many external links',
    'More than 40 links to other websites in one field (high above 100). Hacked posts often get a block of dozens of spam links appended.',
    'Resource round-ups and "top 50" lists.'),
  'canonical-hijack': r('canonical-hijack', 'links', 'high', 'Canonical URL points to another site',
    'The SEO "canonical URL" tells Google that the real version of this page lives on another site, which hands your ranking to that site.',
    'Syndicated press releases that intentionally credit the original publisher.'),
  'insecure-url': r('insecure-url', 'links', 'low', 'Insecure (http://) link',
    'A profile, menu, social or redirect link that uses http:// instead of https://. It can be intercepted or hijacked.'),

  'spam-link': r('spam-link', 'spam', 'high', 'Spam link',
    'A link whose text or address contains spam words (pharma, casino/betting, payday loans, adult, crypto scams, essay writing, replicas, bought followers/backlinks).'),
  'spam-keywords': r('spam-keywords', 'spam', 'medium', 'Cluster of spam keywords',
    'Several different spam phrases in the same field (high when there are many). Single mentions are ignored on purpose.',
    'An article that reports on online gambling or pharmacy scams.'),
  'spam-name': r('spam-name', 'spam', 'medium', 'Spam words in a name or title',
    'A title, name, slug, label or other short field contains a spam phrase. Hacked sites get spam categories, tags and authors created.'),

  'dangerous-file': r('dangerous-file', 'media', 'critical', 'Dangerous file type',
    'An uploaded file that can run code on a server or in a browser (.php, .phtml, .js, .html, .svg, .exe, ...), or whose type (MIME) is not an image or PDF. Web shells are uploaded this way.'),
  'double-extension': r('double-extension', 'media', 'high', 'Double file extension',
    'A file named like shell.php.jpg or photo.jpg.php, a trick to sneak scripts past upload filters.'),
  'mime-mismatch': r('mime-mismatch', 'media', 'high', 'File type does not match its name',
    'The stored file type (e.g. text/html) does not match the extension (e.g. .jpg). Disguised files are a common upload attack.'),
  'offsite-media': r('offsite-media', 'media', 'medium', 'Media imported from another site',
    'The original WordPress URL of this file is not on canadiansme.ca. Injected images can point to tracking or malware hosts.'),

  'admin-account': r('admin-account', 'users', 'low', 'Admin account (review)',
    'Every account with the Admin role is listed so you can confirm you recognise it. Rogue admin users are how attackers keep access after a hack.'),
  'many-admins': r('many-admins', 'users', 'medium', 'Many admin accounts',
    'More than 3 accounts have the Admin role. Give people the lowest role they need.'),
  'new-admin': r('new-admin', 'users', 'medium', 'Recently created admin',
    'An Admin account created in the last 30 days. Make sure someone on the team created it on purpose.'),
  'mixed-automation-role': r('mixed-automation-role', 'users', 'high', 'Automation account with extra roles',
    'An API-key (Automation) account that also has Admin/Editor/Author. A leaked key for this account could do much more than a bot should. Bots should only have the Automation role.'),
  'api-key-on-person': r('api-key-on-person', 'users', 'medium', 'API key on a staff account',
    'A person (not an Automation account) has an API key enabled. Keys never expire and skip the login lockout; use a dedicated Automation user instead.'),
  'never-logged-in': r('never-logged-in', 'users', 'low', 'Account never logged in',
    'An account older than 30 days with no login in the activity log. Unused accounts should be removed.',
    'Automation accounts (they use API keys) and accounts created before the activity log existed.'),
  'account-locked': r('account-locked', 'users', 'medium', 'Account locked',
    'The account is locked after too many wrong passwords. Someone may be guessing its password.'),
  'failed-logins': r('failed-logins', 'users', 'medium', 'Repeated failed logins',
    '5 or more failed logins for the same email address in the last 7 days.'),
  'brute-force-ip': r('brute-force-ip', 'users', 'high', 'Password guessing from one IP',
    '10 or more failed logins from the same IP address in the last 7 days. Consider blocking it in the Vercel firewall.'),
  'suspicious-email': r('suspicious-email', 'users', 'high', 'Account with a throw-away email',
    'A user email on a disposable-mail service or a spam-heavy domain ending. Staff accounts should use company addresses.'),

  'external-redirect': r('external-redirect', 'redirects', 'low', 'Redirect to another website',
    'A redirect that sends visitors off canadiansme.ca. Fine when intended (e.g. to a partner), but hacks add redirects to spam sites.'),
  'suspicious-redirect': r('suspicious-redirect', 'redirects', 'high', 'Redirect to a suspicious address',
    'A redirect to a suspicious domain, a shortened link, a raw IP address, a javascript: URL or a spam address.'),
  'spam-redirect-path': r('spam-redirect-path', 'redirects', 'medium', 'Spam words in a redirect path',
    'A redirect whose "from" path contains spam words, e.g. /cheap-viagra-online/. Hacks create such pages for search engines.'),
  'social-link-mismatch': r('social-link-mismatch', 'settings', 'medium', 'Social link points to the wrong site',
    'A social-media link in Site settings does not go to that network (e.g. the Facebook link goes to another domain).'),

  'scan-error': r('scan-error', 'settings', 'low', 'Could not scan',
    'The scanner could not read this item. Try again; if it keeps happening, check the server logs.'),
}

// ---------------------------------------------------------------------------------------------
// Dictionaries
// ---------------------------------------------------------------------------------------------

/**
 * Top-level domains that are overwhelmingly used for spam, phishing and malware
 * (based on Spamhaus / Interisle abuse statistics), plus country domains typical in
 * WordPress spam injections. Deliberately excludes common startup endings (.io, .ai, .co,
 * .app, .shop, .store, .online, .site).
 */
export const SUSPICIOUS_TLDS: string[] = [
  'ru', 'su', 'cn', 'top', 'xyz', 'click', 'loan', 'loans', 'work', 'bid', 'win', 'date', 'racing',
  'download', 'stream', 'review', 'trade', 'party', 'men', 'accountant', 'cricket', 'science',
  'faith', 'webcam', 'country', 'gdn', 'kim', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'ws', 'buzz',
  'rest', 'fit', 'icu', 'cyou', 'cfd', 'sbs', 'monster', 'quest', 'lol', 'mom', 'bar', 'casino',
  'bet', 'poker', 'porn', 'sex', 'xxx', 'adult', 'sexy', 'cam', 'beauty', 'hair', 'makeup',
  'skin', 'boats', 'autos', 'yachts', 'zip', 'mov',
]

/** URL shorteners (hide the real target, which can be changed at any time). */
export const URL_SHORTENERS: string[] = [
  'bit.ly', 'bitly.com', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly',
  'rebrand.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'v.gd', 's.id', 'adf.ly', 'shorte.st',
  'ouo.io', 'linkvertise.com', 't.ly', 'bl.ink', 'soo.gd', 'clck.ru', 'qr.ae', 'shorturl.asia',
  'tr.im', 'x.co', 'po.st', 'mcaf.ee', 'su.pr', 'bc.vc', 'u.to', 'lnkd.in',
]

/** Click-tracking hosts used by press-release wires; their links legitimately hide the target. */
const TRACKING_HOSTS: string[] = [
  'c212.net', 'prn.to', 'newswire.ca', 'prnewswire.com', 'cts.businesswire.com', 'businesswire.com',
  'globenewswire.com', 'lnkd.in', 't.co', 'l.facebook.com', 'lm.facebook.com', 'google.com',
  'safelinks.protection.outlook.com', 'urldefense.com', 'mailchi.mp', 'list-manage.com',
  'eepurl.com', 'hubspotlinks.com', 'hs-sites.com', 'sendgrid.net', 'mandrillapp.com',
]

/** Disposable / throw-away email providers. */
export const DISPOSABLE_EMAIL_DOMAINS: string[] = [
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'sharklasers.com', 'grr.la',
  'yopmail.com', 'yopmail.net', 'tempmail.com', 'temp-mail.org', 'temp-mail.io', '10minutemail.com',
  '10minutemail.net', 'throwawaymail.com', 'trashmail.com', 'getnada.com', 'nada.email',
  'dispostable.com', 'maildrop.cc', 'mailnesia.com', 'mintemail.com', 'fakeinbox.com',
  'spamgourmet.com', 'mohmal.com', 'emailondeck.com', 'moakt.com', 'tempail.com', 'mail.tm',
  'tmpmail.org', 'burnermail.io', 'cock.li', 'spambox.us', 'mailcatch.com', 'tempinbox.com',
] // Addresses on a suspicious TLD (e.g. .ru, .xyz) are reported too, see isSuspiciousEmail().

type SpamTerm = { category: string; re: RegExp }

// Separator between words: spaces, hyphens, underscores, plus signs, dots (as in URLs).
const S = '(?:[\\s\\-_+.]|%20)*'
const term = (category: string, source: string): SpamTerm => ({
  category,
  re: new RegExp(`(?:^|[^a-z0-9])(?:${source.replace(/ /g, S)})(?=$|[^a-z0-9])`, 'i'),
})

/**
 * Spam phrases that a Canadian small-business magazine would almost never use legitimately.
 * Written as regular-expression fragments; a space means "any separator" (space, -, _, +, .).
 */
export const SPAM_TERMS: SpamTerm[] = [
  // pharma
  ...['viagra', 'cialis', 'levitra', 'kamagra', 'tadalafil', 'sildenafil', 'tramadol', 'xanax',
    'valium', 'oxycodone', 'oxycontin', 'phentermine', 'ambien', 'adderall', 'soma pills?',
    'hydrocodone', 'propecia', 'clomid', 'modafinil', 'erectile dysfunction pills?',
    '(?:no|without) prescription (?:pills?|meds|drugs|needed)', 'buy (?:cheap )?pills?', 'cheap meds',
    'diet pills?', 'weight loss pills?', 'male enhancement', 'penis (?:enlargement|pills?)',
  ].map((s) => term('pharma', s)),
  // casino / betting
  ...['online casinos?', 'casino (?:bonus|online|games?|sites?|no deposit)', 'free spins',
    'no deposit bonus', 'slots? (?:online|gacor|machines? online)', 'slot gacor', 'situs (?:slot|judi|togel)',
    'judi (?:online|bola|slot)', 'togel', 'bandar (?:bola|togel|judi)', 'sbobet',
    'betting (?:tips|sites?|odds)', 'online betting', 'poker online', 'online poker', '1xbet',
    'mostbet', 'pin ?up casino', 'live casino', 'roulette online', 'baccarat online',
    'casino en ligne', 'gacor', 'maxwin', 'rtp slot',
  ].map((s) => term('casino', s)),
  // payday / predatory loans
  ...['pay ?day loans?', 'cash advance (?:online|loans?)', 'title loans?',
    'bad credit loans?', 'loans? (?:with )?no credit check', 'no credit check loans?',
    'instant (?:loan|cash) approval', 'guaranteed (?:loan )?approval loans?', 'fast cash loans?',
    'quick loans? online', 'installment loans? online', 'same day loans?',
  ].map((s) => term('loans', s)),
  // adult
  ...['porn', 'porno', 'xxx (?:videos?|movies?|sex)', 'sex (?:cams?|videos?|chat|dating)',
    'cam ?girls?', 'webcam (?:sex|girls?)', 'adult dating', 'escort (?:service|girls?|agency)',
    'hot (?:girls|singles) (?:near|in)', 'hookup (?:sites?|apps?|tonight)', 'nude (?:pics|photos|girls)',
    'onlyfans leaks?', 'milf', 'hentai',
  ].map((s) => term('adult', s)),
  // crypto / investment scams
  ...['crypto giveaway', 'bitcoin (?:doubler|generator|giveaway)', 'double your (?:bitcoin|btc|crypto)',
    'binary options', 'forex signals', 'crypto recovery (?:service|expert)', 'recover (?:lost|stolen) (?:crypto|bitcoin)',
    'bitcoin investment platform', 'guaranteed daily (?:profit|returns?)', 'elon musk giveaway',
    'free (?:bitcoin|btc|usdt)', 'wallet validation', 'airdrop claim',
  ].map((s) => term('crypto', s)),
  // essay / homework mills
  ...['essay writing services?', 'write my (?:essay|paper|assignment)', 'buy (?:an )?essays?',
    'cheap essays?', 'paper writing services?', 'dissertation (?:help|writing service)',
    'do my homework', 'assignment help', 'term papers? for sale', 'custom essays?',
  ].map((s) => term('essay', s)),
  // replica / counterfeit
  ...['replica (?:watches|rolex|handbags|bags|designer)', 'rolex replica', 'fake rolex',
    'cheap (?:nfl |nba |mlb |nhl )?jerseys', 'ugg (?:boots )?(?:outlet|sale)', 'louis vuitton (?:outlet|replica)',
    'michael kors outlet', 'cheap (?:oakley|ray ban) sunglasses', 'designer replicas?', 'knockoff (?:bags|watches)',
  ].map((s) => term('replica', s)),
  // bought engagement / SEO spam / hacking lures
  ...['buy (?:instagram|tiktok|youtube|twitter) (?:followers|likes|views)', 'cheap followers',
    'buy backlinks', 'seo backlinks', 'pbn links', 'guest post (?:service|for sale)',
    'free robux', 'v ?bucks generator', 'hack (?:whatsapp|instagram|facebook) account',
    'spy app', 'cracked (?:apk|software)', 'keygen', 'warez',
  ].map((s) => term('seo-spam', s)),
]

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

const MAX_INPUT = 1_000_000 // characters; longer fields are scanned up to this point

/** Collapses whitespace and cuts to at most `max` characters (raw text; the UI escapes it). */
export const clip = (s: string, max = 160): string => {
  const one = String(s ?? '').replace(/\s+/g, ' ').trim()
  return one.length > max ? `${one.slice(0, max - 1)}…` : one
}

/** A ≤160-character excerpt around position `index` of `text`. */
export const excerptAt = (text: string, index: number, matchLength = 0): string => {
  const start = Math.max(0, index - 50)
  const end = Math.min(text.length, index + Math.max(matchLength, 0) + 110)
  const pre = start > 0 ? '…' : ''
  return clip(pre + text.slice(start, end))
}

const ENTITY_MAP: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', colon: ':', tab: '\t', newline: '\n' }

/** Decodes HTML entities (named basics + numeric), as a browser would before following a URL. */
export const decodeEntities = (s: string): string =>
  String(s ?? '').replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);?/gi, (m, code: string) => {
    const c = code.toLowerCase()
    if (c.startsWith('#x')) {
      const n = parseInt(c.slice(2), 16)
      return Number.isFinite(n) && n < 0x110000 ? String.fromCodePoint(n) : m
    }
    if (c.startsWith('#')) {
      const n = parseInt(c.slice(1), 10)
      return Number.isFinite(n) && n < 0x110000 ? String.fromCodePoint(n) : m
    }
    return ENTITY_MAP[c] ?? m
  })

/** HTML → visible-ish text (tags removed, entities decoded). */
export const stripTags = (html: string): string =>
  decodeEntities(
    String(html ?? '')
      .replace(/<(script|style)\b[\s\S]*?<\/\1\s*>/gi, ' ')
      .replace(/<[^<>]*>/g, ' '),
  )
    .replace(/\s+/g, ' ')
    .trim()

/** Lower-case host name of an absolute (or protocol-relative) URL, or '' for relative links. */
export const hostOf = (url: string): string => {
  const u = String(url ?? '').trim()
  if (!/^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(u)) return ''
  try {
    const parsed = new URL(u.startsWith('//') ? `https:${u}` : u)
    return parsed.hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '')
  } catch {
    const m = u.match(/^(?:[a-z][a-z0-9+.-]*:)?\/\/([^/?#:\s]+)/i)
    return m ? m[1].toLowerCase() : ''
  }
}

const hostMatches = (host: string, domain: string) => host === domain || host.endsWith(`.${domain}`)

const tldOf = (host: string) => host.split('.').pop() || ''

/** example.co.uk → co.uk is not handled; good enough for "is this the same site?" checks. */
const baseDomain = (host: string) => host.replace(/^www\d?\./, '').split('.').slice(-2).join('.')

const isIpHost = (host: string) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || (host.includes(':') && /^[0-9a-f:]+$/i.test(host))

export const DEFAULT_OWN_HOSTS = ['canadiansme.ca']

/** True for canadiansme.ca, its sub-domains and any extra hosts passed in `ownHosts`. */
export const isOwnHost = (host: string, ownHosts: string[] = []): boolean =>
  Boolean(host) && [...DEFAULT_OWN_HOSTS, ...ownHosts].filter(Boolean).some((d) => hostMatches(host, d.toLowerCase()))

export const isAllowedEmbedHost = (host: string): boolean =>
  ALLOWED_IFRAME_HOSTS.some((h) => host === h.toLowerCase())

export const isShortenerHost = (host: string): boolean => URL_SHORTENERS.some((d) => hostMatches(host, d))

export const isSuspiciousTld = (host: string): boolean => Boolean(host) && SUSPICIOUS_TLDS.includes(tldOf(host))

/** Removes whitespace/control characters browsers ignore inside a URL scheme ("java\tscript:"). */
const normaliseUrl = (raw: string) => decodeEntities(raw).replace(/[\u0000- \u007f-\u009f]+/g, '').trim()

/** javascript: / vbscript: / livescript: — always executes code. */
const isScriptScheme = (url: string) => /^(?:javascript|vbscript|livescript|mocha):/i.test(normaliseUrl(url))

/** data: URLs other than ordinary images. */
const isDangerousData = (url: string) => {
  const u = normaliseUrl(url).toLowerCase()
  return u.startsWith('data:') && !/^data:image\/(?:png|jpe?g|gif|webp|avif|bmp);/.test(u)
}

/** Turns a URL or slug into words so the spam dictionary can read it. */
const urlToWords = (url: string) => {
  let u = String(url ?? '')
  try {
    u = decodeURIComponent(u)
  } catch {
    // keep raw
  }
  return u.replace(/^[a-z]+:\/\//i, ' ').replace(/[\/\-_+.=?&#%:]+/g, ' ')
}

/** Spam terms found in `text`: distinct term count, total matches and the first match. */
export const findSpamTerms = (text: string) => {
  const t = String(text ?? '').slice(0, MAX_INPUT)
  const distinct: { category: string; match: string; index: number }[] = []
  let total = 0
  for (const s of SPAM_TERMS) {
    const g = new RegExp(s.re.source, 'gi')
    let m: RegExpExecArray | null
    let first: RegExpExecArray | null = null
    let n = 0
    while ((m = g.exec(t)) && n < 50) {
      if (!first) first = m
      n++
      if (m[0].length === 0) g.lastIndex++
    }
    if (first) {
      const match = first[0].replace(/^[^a-z0-9]+/i, '').trim()
      // Two dictionary entries can match the same words; count each phrase once.
      if (!distinct.some((d) => d.match.toLowerCase() === match.toLowerCase())) {
        distinct.push({ category: s.category, match, index: first.index })
      }
      total += n
    }
  }
  distinct.sort((a, b) => a.index - b.index)
  return { distinct, total, categories: [...new Set(distinct.map((d) => d.category))] }
}

export const hasSpamTerm = (text: string): boolean => SPAM_TERMS.some((s) => s.re.test(String(text ?? '')))

export const isSuspiciousEmail = (email: string): boolean => {
  const domain = String(email ?? '').toLowerCase().split('@')[1] || ''
  if (!domain) return false
  return DISPOSABLE_EMAIL_DOMAINS.some((d) => hostMatches(domain, d)) || isSuspiciousTld(domain)
}

// ---------------------------------------------------------------------------------------------
// Hit collection
// ---------------------------------------------------------------------------------------------

/** Merges repeated matches of the same rule into one hit (first excerpt, highest severity, count). */
export class HitList {
  map = new Map<RuleId, RuleHit>()

  add(rule: RuleId, excerpt: string, severity: Severity = RULES[rule].severity, count = 1): void {
    const prev = this.map.get(rule)
    if (!prev) {
      this.map.set(rule, { rule, severity, excerpt: clip(excerpt), count })
      return
    }
    prev.count += count
    if (SEVERITY_RANK[severity] > SEVERITY_RANK[prev.severity]) {
      prev.severity = severity
      prev.excerpt = clip(excerpt)
    }
  }

  addAll(hits: RuleHit[]): void {
    for (const h of hits) this.add(h.rule, h.excerpt, h.severity, h.count)
  }

  list(): RuleHit[] {
    return [...this.map.values()].sort((a, b) => compareSeverity(a.severity, b.severity))
  }
}

// ---------------------------------------------------------------------------------------------
// URL rules
// ---------------------------------------------------------------------------------------------

export type UrlScanOptions = ScanOptions & {
  /** Report http:// links (profiles, menus, redirects). Off for article bodies (too noisy). */
  requireHttps?: boolean
  /** Text shown for the link, used for the "cloaked link" and spam-text checks. */
  linkText?: string
}

/** Checks one URL (a link, an embed address, a profile link, a redirect target). */
export const scanUrl = (rawUrl: string, opts: UrlScanOptions = {}): RuleHit[] => {
  const hits = new HitList()
  const url = String(rawUrl ?? '').trim()
  if (!url) return []
  const shown = opts.linkText ? `${clip(opts.linkText, 50)} → ${url}` : url

  if (isScriptScheme(url)) hits.add('dangerous-url', shown, 'critical')
  else if (isDangerousData(url)) hits.add('dangerous-url', shown, 'high')

  const host = hostOf(url)
  if (host && !isOwnHost(host, opts.ownHosts)) {
    if (isIpHost(host)) hits.add('ip-address-link', shown)
    if (isSuspiciousTld(host)) hits.add('suspicious-domain', shown)
    if (isShortenerHost(host)) hits.add('url-shortener', shown)
    if (opts.requireHttps && /^http:\/\//i.test(url)) hits.add('insecure-url', shown)

    // Link text that looks like a different web address than the real target.
    const text = (opts.linkText || '').trim()
    const textHost = text.match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\/?#]\S*)?$/i)?.[1]?.toLowerCase()
    if (textHost && baseDomain(textHost) !== baseDomain(host) && !TRACKING_HOSTS.some((d) => hostMatches(host, d))) {
      hits.add('cloaked-link', shown)
    }
  } else if (opts.requireHttps && /^http:\/\//i.test(url) && host) {
    hits.add('insecure-url', shown)
  }

  if (hasSpamTerm(urlToWords(url)) || (opts.linkText && hasSpamTerm(opts.linkText))) {
    hits.add('spam-link', shown)
  }
  return hits.list()
}

// ---------------------------------------------------------------------------------------------
// HTML rules
// ---------------------------------------------------------------------------------------------

// The attribute part stops at the next "<" and is length-bounded, so malformed markup
// (thousands of unclosed "<a ") cannot make the scan slow (no catastrophic backtracking).
const TAG_RE = /<([a-zA-Z][a-zA-Z0-9:-]*)\b([^<>]{0,4000})>/g
const ATTR_RE = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g

const parseAttrs = (raw: string): Record<string, string> => {
  const out: Record<string, string> = {}
  ATTR_RE.lastIndex = 0
  let m: RegExpExecArray | null
  let guard = 0
  while ((m = ATTR_RE.exec(raw)) && guard++ < 200) {
    const name = m[1].toLowerCase()
    if (!(name in out)) out[name] = m[2] ?? m[3] ?? m[4] ?? ''
  }
  return out
}

/** True when an inline style hides the element from visitors (but not from search engines). */
export const isHiddenStyle = (style: string): boolean => {
  const s = decodeEntities(String(style ?? '')).toLowerCase().replace(/\s+/g, '')
  if (!s) return false
  if (/(?:^|;)display:none/.test(s)) return true
  if (/(?:^|;)visibility:hidden/.test(s)) return true
  if (/(?:^|;)font-size:0+(?:\.0+)?(?:px|pt|em|rem|%)?(?:;|!|$)/.test(s)) return true
  if (/(?:^|;)opacity:0+(?:\.0+)?(?:;|!|$)/.test(s)) return true
  if (/(?:^|;)(?:left|top|right|bottom|text-indent|margin-left|margin-top):-\d{3,}/.test(s)) return true
  if (/(?:^|;)(?:height|width|max-height|max-width):[01](?:px)?(?:;|!|$)/.test(s) && /overflow:hidden/.test(s)) return true
  if (/(?:^|;)clip:rect\(0/.test(s) || /(?:^|;)transform:scale\(0\)/.test(s)) return true
  if (/(?:^|;)color:(?:#fff(?:fff)?|white|transparent)(?:;|!|$)/.test(s) && /font-size:[0-2]px/.test(s)) return true
  return false
}

const URL_ATTRS = ['href', 'src', 'action', 'formaction', 'data', 'poster', 'background', 'xlink:href', 'srcdoc', 'lowsrc', 'dynsrc']
const EMBED_TAGS = new Set(['iframe', 'frame', 'frameset', 'embed', 'object', 'applet', 'portal'])

const OBFUSCATION: RegExp[] = [
  /\beval\s*\(/gi,
  /\batob\s*\(/gi,
  /String\s*\.\s*fromCharCode\s*\(/gi,
  /document\s*\.\s*write(?:ln)?\s*\(/gi,
  /\bunescape\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*["'`]/gi,
  /(?:\\x[0-9a-fA-F]{2}){8,}/g,
  /(?:\\u00[0-9a-fA-F]{2}){8,}/g,
  /\b_0x[0-9a-f]{4,6}\b/gi,
  /document\s*\.\s*createElement\s*\(\s*["']script/gi,
  /\.\s*fromCharCode\s*\.\s*apply\s*\(/gi,
]

const JS_REDIRECT: RegExp[] = [
  /(?:window|document|top|self|parent)\s*\.\s*location(?:\s*\.\s*href)?\s*=(?!=)/gi,
  /\blocation\s*\.\s*href\s*=(?!=)/gi,
  /\blocation\s*\.\s*(?:replace|assign)\s*\(/gi,
]

const ENCODED: RegExp[] = [/(?:&#x?[0-9a-fA-F]{2,6};){20,}/g, /(?:%[0-9a-fA-F]{2}){30,}/g]

const BASE64_RE = /[A-Za-z0-9+\/]{200,}={0,2}/g

const firstMatch = (re: RegExp, text: string): { index: number; length: number; count: number } | null => {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`)
  let m: RegExpExecArray | null
  let first: { index: number; length: number } | null = null
  let count = 0
  while ((m = g.exec(text)) && count < 100) {
    if (!first) first = { index: m.index, length: m[0].length }
    count++
    if (m[0].length === 0) g.lastIndex++
  }
  return first ? { ...first, count } : null
}

const looksLikeCode = (b64: string): boolean => {
  try {
    const chunk = b64.replace(/=+$/, '').slice(0, 400)
    const decoded = typeof atob === 'function' ? atob(chunk.slice(0, chunk.length - (chunk.length % 4))) : ''
    return /<script|<iframe|eval\s*\(|function\s*\(|https?:\/\/|document\.|window\./i.test(decoded)
  } catch {
    return false
  }
}

/**
 * Scans an HTML string (WordPress legacyHtml, Custom HTML blocks, the article footer, or
 * plain text that might contain injected HTML).
 */
export const scanHtml = (input: string, opts: ScanOptions = {}): RuleHit[] => {
  const html = String(input ?? '').slice(0, MAX_INPUT)
  if (!html.trim()) return []
  const hits = new HitList()
  const ownHosts = opts.ownHosts || []
  const maxExternal = opts.maxExternalLinks ?? 40
  let externalLinks = 0

  // ---- tag by tag ----
  TAG_RE.lastIndex = 0
  let m: RegExpExecArray | null
  let tags = 0
  while ((m = TAG_RE.exec(html)) && tags++ < 50_000) {
    const tag = m[0]
    const name = m[1].toLowerCase()
    const attrs = parseAttrs(m[2] || '')
    const at = m.index

    if (name === 'script') {
      const src = attrs.src ? ` (loads ${hostOf(attrs.src) || attrs.src})` : ''
      hits.add('script-tag', `${clip(tag, 120)}${src}`)
    }

    for (const attr of Object.keys(attrs)) {
      if (/^on[a-z]{3,}$/.test(attr)) hits.add('event-handler', clip(tag))
    }

    for (const attr of URL_ATTRS) {
      const v = attrs[attr]
      if (v === undefined) continue
      if (isScriptScheme(v)) hits.add('dangerous-url', clip(tag), 'critical')
      else if (isDangerousData(v)) hits.add('dangerous-url', clip(tag), 'high')
    }
    if (attrs.style && /expression\s*\(|javascript:|behavior\s*:|-moz-binding/i.test(decodeEntities(attrs.style))) {
      hits.add('dangerous-url', clip(tag), 'high')
    }

    if (EMBED_TAGS.has(name)) {
      const src = attrs.src || attrs.data || attrs.code || ''
      const host = hostOf(src)
      if (attrs.srcdoc !== undefined || !host || !isAllowedEmbedHost(host)) {
        hits.add('untrusted-embed', `${clip(tag, 120)}${host ? ` (${host})` : ''}`)
      }
    }

    if (name === 'form') {
      const host = hostOf(attrs.action || '')
      hits.add('external-form', clip(tag), host && !isOwnHost(host, ownHosts) ? 'high' : 'medium')
    }

    if (name === 'meta') {
      if (/refresh/i.test(attrs['http-equiv'] || '')) hits.add('meta-refresh', clip(tag))
      else hits.add('style-or-base-tag', clip(tag), 'low')
    }
    if (name === 'base') hits.add('style-or-base-tag', clip(tag), 'high')
    if (name === 'style') hits.add('style-or-base-tag', excerptAt(html, at, 0))
    if (name === 'link' && /stylesheet|import|preload|prefetch|dns-prefetch|preconnect/i.test(attrs.rel || '')) {
      hits.add('style-or-base-tag', clip(tag))
    }

    // Links: spam, suspicious hosts, flood counting.
    if (name === 'a' && attrs.href !== undefined) {
      const close = html.slice(TAG_RE.lastIndex, TAG_RE.lastIndex + 2000).search(/<\/a\s*>/i)
      const inner = close >= 0 ? html.slice(TAG_RE.lastIndex, TAG_RE.lastIndex + close) : ''
      const text = stripTags(inner)
      const href = decodeEntities(attrs.href)
      const host = hostOf(href)
      if (host && !isOwnHost(host, ownHosts)) externalLinks++
      for (const h of scanUrl(href, { ownHosts, linkText: text })) {
        if (h.rule !== 'dangerous-url') hits.add(h.rule, h.excerpt, h.severity)
      }
    }

    // Hidden content (and whether it hides links or spam).
    const hidden = (attrs.style !== undefined && isHiddenStyle(attrs.style)) || attrs.hidden !== undefined
    if (hidden && !/^(?:br|hr|img|input|meta|link|source|track|wbr|col|area|param)$/.test(name)) {
      const after = html.slice(TAG_RE.lastIndex, TAG_RE.lastIndex + 5000)
      const closeAt = after.search(new RegExp(`</${name.replace(/[^a-z0-9:-]/g, '')}\\s*>`, 'i'))
      const region = tag + (closeAt >= 0 ? after.slice(0, closeAt) : after.slice(0, 1000))
      const hasLink = /<a\b[^>]*\bhref\s*=/i.test(region) || (name === 'a' && attrs.href !== undefined)
      const text = stripTags(region)
      if (hasLink || hasSpamTerm(text)) {
        const href = region.match(/\bhref\s*=\s*["']?([^"'\s>]+)/i)?.[1]
        hits.add('hidden-link', `${clip(tag, 80)} ${clip(text, 40)}${href ? ` → ${href}` : ''}`)
      } else if (text.length > 20) {
        hits.add('hidden-content', `${clip(tag, 80)} ${text}`)
      }
    }
  }

  // Fallback for script tags the tag parser could not read (e.g. a "<" inside an attribute).
  if (!hits.map.has('script-tag')) {
    const f = firstMatch(/<script\b/gi, html)
    if (f) hits.add('script-tag', excerptAt(html, f.index, 60), 'critical', f.count)
  }
  if (!hits.map.has('event-handler')) {
    const f = firstMatch(/\son(?:error|load|click|mouse[a-z]+|focus|blur|change|submit|input|key[a-z]+|animation[a-z]+|transition[a-z]+|begin|toggle|pageshow|wheel|pointer[a-z]+|touch[a-z]+)\s*=/gi, html)
    if (f) hits.add('event-handler', excerptAt(html, f.index, 60), 'high', f.count)
  }

  if (externalLinks > maxExternal) {
    hits.add('external-link-flood', `${externalLinks} links to other websites`, externalLinks > 100 ? 'high' : 'medium')
  }

  // ---- text patterns over the whole string ----
  for (const re of OBFUSCATION) {
    const f = firstMatch(re, html)
    if (f) hits.add('obfuscated-js', excerptAt(html, f.index, f.length), 'high', f.count)
  }
  for (const re of JS_REDIRECT) {
    const f = firstMatch(re, html)
    if (f) hits.add('js-redirect', excerptAt(html, f.index, f.length), 'critical', f.count)
  }
  for (const re of ENCODED) {
    const f = firstMatch(re, html)
    if (f) hits.add('encoded-text', excerptAt(html, f.index, Math.min(f.length, 60)), 'medium', f.count)
  }
  {
    const g = new RegExp(BASE64_RE.source, 'g')
    let b: RegExpExecArray | null
    let n = 0
    while ((b = g.exec(html)) && n < 200) {
      n++
      const before = html.slice(Math.max(0, b.index - 60), b.index)
      if (/data:image\/(?:png|jpe?g|gif|webp|avif|bmp);base64,\s*$/i.test(before)) continue
      // Long words of letters only (e.g. a URL slug) are not base64 payloads.
      if (!/[0-9+\/]/.test(b[0]) || !/[A-Z]/.test(b[0]) || !/[a-z]/.test(b[0])) continue
      const severe = looksLikeCode(b[0]) || b[0].length >= 2000
      hits.add('base64-blob', `${b[0].length} characters: ${b[0].slice(0, 80)}…`, severe ? 'high' : 'medium')
    }
  }

  // ---- spam keyword cluster in the visible text ----
  const text = stripTags(html)
  const spam = findSpamTerms(text)
  if (spam.distinct.length >= 3 || spam.total >= 5) {
    const words = spam.distinct.slice(0, 6).map((d) => d.match).join(', ')
    hits.add(
      'spam-keywords',
      `${spam.distinct.length} spam phrases (${spam.categories.join(', ')}): ${words}`,
      spam.distinct.length >= 6 || spam.categories.length >= 3 ? 'high' : 'medium',
      spam.total,
    )
  }

  return hits.list()
}

/**
 * Short single-line fields (titles, names, slugs, menu labels, SEO titles): any spam phrase
 * counts, plus the HTML rules in case markup was injected.
 */
export const scanName = (value: string, opts: ScanOptions = {}): RuleHit[] => {
  const v = String(value ?? '')
  if (!v.trim()) return []
  const hits = new HitList()
  if (/[<>]|&#|javascript:|%3c/i.test(v)) hits.addAll(scanHtml(v, opts))
  const spam = findSpamTerms(`${v} ${urlToWords(v)}`)
  if (spam.distinct.length) hits.add('spam-name', `${clip(v, 100)} (${spam.distinct.map((d) => d.match).join(', ')})`)
  return hits.list()
}

/**
 * Longer plain-text fields (excerpts, SEO descriptions, bios, descriptions): HTML rules
 * (they should not contain markup at all) plus spam clusters. A single spam phrase next to a
 * bare URL also counts, because spam comments/bios usually look like "best casino https://...".
 */
export const scanText = (value: string, opts: ScanOptions = {}): RuleHit[] => {
  const v = String(value ?? '')
  if (!v.trim()) return []
  const hits = new HitList()
  hits.addAll(scanHtml(v, opts))
  const urls = v.match(/\bhttps?:\/\/[^\s"'<>]+/gi) || []
  for (const u of urls.slice(0, 50)) {
    for (const h of scanUrl(u, opts)) hits.add(h.rule, h.excerpt, h.severity)
  }
  if (urls.length && hasSpamTerm(v)) {
    const spam = findSpamTerms(v)
    hits.add('spam-link', `${spam.distinct.map((d) => d.match).join(', ')} + ${urls[0]}`)
  }
  return hits.list()
}

// ---------------------------------------------------------------------------------------------
// Lexical (rich-text editor) content
// ---------------------------------------------------------------------------------------------

const escText = (s: unknown) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
const escAttr = (s: unknown) => escText(s).replace(/"/g, '&quot;')

/**
 * Turns the rich-text editor's JSON into HTML for scanning. Unlike the real renderer it keeps
 * every URL exactly as stored (javascript: links included) so they can be reported, while the
 * text the editor typed is escaped (mentioning "<script>" in a sentence is not a script).
 * Custom HTML blocks are included raw because that is how the website outputs them.
 */
export const lexicalToScanHtml = (value: unknown): string => {
  const root = (value as { root?: unknown } | null | undefined)?.root
  if (!root || typeof root !== 'object') return ''
  const out: string[] = []
  let nodes = 0
  const walk = (n: any): void => {
    if (!n || typeof n !== 'object' || nodes++ > 100_000) return
    const f = (n.fields && typeof n.fields === 'object' ? n.fields : {}) as Record<string, unknown>
    if (n.type === 'text' || typeof n.text === 'string') {
      out.push(escText(n.text))
      return
    }
    if (n.type === 'link' || n.type === 'autolink') {
      const href = f.linkType === 'internal' ? '/internal-link' : (f.url as string) || (n.url as string) || ''
      out.push(`<a href="${escAttr(href)}">`)
      ;(Array.isArray(n.children) ? n.children : []).forEach(walk)
      out.push('</a>')
      return
    }
    if (n.type === 'block') {
      if (f.blockType === 'html' && typeof f.html === 'string') out.push(`\n${f.html}\n`)
      else if (f.blockType === 'embed' && typeof f.url === 'string') {
        out.push(`<a href="${escAttr(f.url)}">${escText(f.caption || f.url)}</a>`)
      } else if (f.blockType === 'callout') {
        out.push(`<aside>${escText(f.text)}`)
        if (f.linkUrl) out.push(` <a href="${escAttr(f.linkUrl)}">${escText(f.linkLabel || 'Learn more')}</a>`)
        out.push('</aside>')
      } else if (typeof f.url === 'string') out.push(`<a href="${escAttr(f.url)}"></a>`)
      return
    }
    if (Array.isArray(n.children)) {
      const blockLevel = ['paragraph', 'heading', 'listitem', 'quote', 'list', 'root'].includes(n.type)
      if (blockLevel) out.push('<p>')
      n.children.forEach(walk)
      if (blockLevel) out.push('</p>\n')
    }
  }
  walk(root)
  return out.join('')
}

// ---------------------------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------------------------

/** Extensions that can run on a server or in a browser. */
export const DANGEROUS_EXTENSIONS: string[] = [
  'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phps', 'phar', 'inc',
  'pl', 'py', 'cgi', 'sh', 'bash', 'rb', 'jsp', 'jspx', 'asp', 'aspx', 'ashx', 'asmx', 'cer',
  'exe', 'dll', 'bat', 'cmd', 'com', 'msi', 'scr', 'vbs', 'vbe', 'wsf', 'hta', 'ps1', 'jar',
  'js', 'mjs', 'cjs', 'html', 'htm', 'xhtml', 'shtml', 'svg', 'svgz', 'xml', 'xsl', 'swf',
  'htaccess', 'user.ini', 'ini', 'config',
]

const EXT_MIME: Record<string, string[]> = {
  jpg: ['image/jpeg', 'image/pjpeg'],
  jpeg: ['image/jpeg', 'image/pjpeg'],
  jpe: ['image/jpeg'],
  png: ['image/png'],
  gif: ['image/gif'],
  webp: ['image/webp'],
  avif: ['image/avif'],
  pdf: ['application/pdf'],
}

/** File types the Media collection accepts (see collections/Media.ts). */
export const SAFE_MIME_TYPES = ['image/jpeg', 'image/pjpeg', 'image/png', 'image/webp', 'image/gif', 'image/avif', 'application/pdf']

/** Checks an uploaded file's name, stored type and original URL. */
export const scanFile = (
  file: { filename?: string | null; mimeType?: string | null; wpUrl?: string | null },
  opts: ScanOptions = {},
): RuleHit[] => {
  const hits = new HitList()
  const name = String(file.filename ?? '').trim()
  const mime = String(file.mimeType ?? '').toLowerCase().trim()
  const checkName = (n: string, label: string) => {
    const lower = n.toLowerCase().replace(/[?#].*$/, '')
    const base = lower.split('/').pop() || ''
    const parts = base.split('.')
    if (parts.length < 2) return
    const ext = parts[parts.length - 1]
    if (DANGEROUS_EXTENSIONS.includes(ext) || base === '.htaccess') hits.add('dangerous-file', `${label}${n}`)
    const inner = parts.slice(1, -1)
    if (inner.some((p) => DANGEROUS_EXTENSIONS.includes(p) && !['com', 'inc', 'config', 'ini', 'xml'].includes(p))) {
      hits.add('double-extension', `${label}${n}`)
    }
    if (mime && EXT_MIME[ext] && !EXT_MIME[ext].includes(mime)) hits.add('mime-mismatch', `${label}${n} is stored as ${mime}`)
  }
  if (name) checkName(name, '')
  if (/\x00|%00/.test(name)) hits.add('double-extension', `${name} (contains a null byte)`)
  if (mime && !SAFE_MIME_TYPES.includes(mime)) hits.add('dangerous-file', `${name || 'file'} is stored as ${mime}`)

  const wp = String(file.wpUrl ?? '').trim()
  if (wp) {
    if (isScriptScheme(wp) || isDangerousData(wp)) hits.add('dangerous-url', wp, 'critical')
    const host = hostOf(wp)
    // Jetpack's image CDN (i0.wp.com/canadiansme.ca/...) also serves the site's own images.
    const jetpack = /^i[0-3]\.wp\.com$/.test(host) && /\/(?:www\.)?canadiansme\.ca\//i.test(wp)
    if (host && !isOwnHost(host, opts.ownHosts) && !jetpack) {
      const s = isSuspiciousTld(host) || isIpHost(host) ? 'high' : 'medium'
      hits.add('offsite-media', wp, s)
    }
    checkName(wp, 'original URL: ')
  }
  return hits.list()
}

// ---------------------------------------------------------------------------------------------
// Social links (Site settings)
// ---------------------------------------------------------------------------------------------

export const SOCIAL_HOSTS: Record<string, string[]> = {
  facebook: ['facebook.com', 'fb.com', 'fb.me'],
  instagram: ['instagram.com'],
  x: ['twitter.com', 'x.com'],
  linkedin: ['linkedin.com'],
  youtube: ['youtube.com', 'youtu.be'],
}

export const scanSocialLink = (network: string, url: string, opts: ScanOptions = {}): RuleHit[] => {
  const v = String(url ?? '').trim()
  if (!v) return []
  const hits = new HitList()
  hits.addAll(scanUrl(v, { ...opts, requireHttps: true }))
  const host = hostOf(v)
  const expected = SOCIAL_HOSTS[network]
  if (expected && (!host || !expected.some((d) => hostMatches(host, d)))) {
    hits.add('social-link-mismatch', `${network}: ${v}`)
  }
  return hits.list()
}
