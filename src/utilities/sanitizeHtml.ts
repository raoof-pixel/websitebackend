import createDOMPurify from 'dompurify'
import { JSDOM } from 'jsdom'

/**
 * Server-side HTML cleaning. Every piece of raw HTML stored in the CMS (imported WordPress
 * content, "Custom HTML" blocks, the article footer) goes through this before it is saved,
 * so injected <script> tags, inline event handlers (onclick=...), javascript: links and
 * hidden iframes from untrusted sites can never reach the public website.
 *
 * This matters because a hacked WordPress database is one of the most common ways spam
 * links and malware end up in post content; cleaning on import stops it being copied over.
 */

/** Only iframes from these hosts survive (videos, maps, podcasts, forms). */
const ALLOWED_IFRAME_HOSTS = [
  'www.youtube.com',
  'youtube.com',
  'www.youtube-nocookie.com',
  'player.vimeo.com',
  'www.google.com', // Google Maps embeds
  'maps.google.com',
  'docs.google.com', // Google Forms / Docs
  'open.spotify.com',
  'w.soundcloud.com',
  'www.linkedin.com',
  'embed.podcasts.apple.com',
  'www.facebook.com',
  'platform.twitter.com',
  'www.instagram.com',
  'player.simplecast.com',
  'www.buzzsprout.com',
  'anchor.fm',
  'podcasters.spotify.com',
  'canadiansme.ca',
  'www.canadiansme.ca',
]

const window = new JSDOM('').window
const DOMPurify = createDOMPurify(window as any)

DOMPurify.addHook('uponSanitizeElement', (node: any, data: any) => {
  if (data.tagName !== 'iframe') return
  const src = node.getAttribute?.('src') || ''
  let ok = false
  try {
    const u = new URL(src, 'https://canadiansme.ca')
    ok = u.protocol === 'https:' && ALLOWED_IFRAME_HOSTS.includes(u.hostname.toLowerCase())
  } catch {
    ok = false
  }
  if (!ok) node.parentNode?.removeChild(node)
})

DOMPurify.addHook('afterSanitizeAttributes', (node: any) => {
  // Links opening a new tab must not get access to window.opener (reverse tabnabbing).
  if (node.tagName === 'A' && node.getAttribute('target') === '_blank') {
    const rel = new Set((node.getAttribute('rel') || '').split(/\s+/).filter(Boolean))
    rel.add('noopener')
    rel.add('noreferrer')
    node.setAttribute('rel', [...rel].join(' '))
  }
  if (node.tagName === 'IFRAME') {
    node.setAttribute('loading', 'lazy')
    node.setAttribute('referrerpolicy', 'strict-origin-when-cross-origin')
  }
})

export const sanitizeHtml = (html: unknown): string => {
  if (typeof html !== 'string' || !html) return ''
  return DOMPurify.sanitize(html, {
    ADD_TAGS: ['iframe'],
    ADD_ATTR: ['allow', 'allowfullscreen', 'frameborder', 'scrolling', 'target', 'loading'],
    FORBID_TAGS: ['script', 'style', 'object', 'embed', 'form', 'input', 'button', 'textarea', 'select', 'base', 'meta', 'link'],
    FORBID_ATTR: ['style', 'srcdoc', 'formaction'],
    ALLOW_DATA_ATTR: false,
    ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|tel):|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
  })
}

/** Field hook: cleans the value before it is saved. */
export const sanitizeHtmlHook = ({ value }: { value?: unknown }) =>
  typeof value === 'string' ? sanitizeHtml(value) : value
