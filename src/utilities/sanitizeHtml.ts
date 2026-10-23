import sanitize from 'sanitize-html'

/**
 * Server-side HTML cleaning. Every piece of raw HTML stored in the CMS (imported WordPress
 * content, "Custom HTML" blocks, the article footer) goes through this before it is saved,
 * so injected <script> tags, inline event handlers (onclick=...), javascript: links, inline
 * styles that hide spam, and iframes from untrusted sites can never reach the public website.
 *
 * A hacked WordPress database is a common way spam links and malware end up in post content;
 * cleaning on import stops it being copied over.
 *
 * Uses sanitize-html (pure JavaScript, allow-list based) so it runs on any serverless runtime.
 */

/** Only iframes from these hosts survive (videos, maps, podcasts, forms). */
const ALLOWED_IFRAME_HOSTS = [
  'www.youtube.com',
  'youtube.com',
  'www.youtube-nocookie.com',
  'player.vimeo.com',
  'www.google.com',
  'maps.google.com',
  'docs.google.com',
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

const OPTIONS: sanitize.IOptions = {
  allowedTags: [
    ...sanitize.defaults.allowedTags,
    'img', 'figure', 'figcaption', 'picture', 'source', 'iframe', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'video', 'audio', 'track', 'del', 'ins', 'sup', 'sub', 'mark', 'small', 'u', 's',
  ],
  disallowedTagsMode: 'discard',
  allowedAttributes: {
    a: ['href', 'name', 'target', 'rel', 'title'],
    img: ['src', 'srcset', 'sizes', 'alt', 'title', 'width', 'height', 'loading'],
    source: ['src', 'srcset', 'type', 'media', 'sizes'],
    iframe: ['src', 'width', 'height', 'allow', 'allowfullscreen', 'frameborder', 'title', 'loading', 'referrerpolicy'],
    video: ['src', 'controls', 'width', 'height', 'poster', 'preload'],
    audio: ['src', 'controls', 'preload'],
    track: ['src', 'kind', 'srclang', 'label'],
    th: ['colspan', 'rowspan', 'scope'],
    td: ['colspan', 'rowspan'],
    ol: ['start', 'type', 'reversed'],
    '*': ['id', 'class'],
  },
  allowedSchemes: ['http', 'https', 'mailto', 'tel'],
  allowedSchemesByTag: { img: ['http', 'https'], iframe: ['https'], source: ['http', 'https'] },
  allowProtocolRelative: false,
  allowedIframeHostnames: ALLOWED_IFRAME_HOSTS,
  allowIframeRelativeUrls: false,
  transformTags: {
    // Links opening a new tab must not get access to window.opener (reverse tabnabbing).
    a: (tagName, attribs) => {
      if (attribs.target === '_blank') {
        const rel = new Set((attribs.rel || '').split(/\s+/).filter(Boolean))
        rel.add('noopener')
        rel.add('noreferrer')
        attribs.rel = [...rel].join(' ')
      }
      return { tagName, attribs }
    },
    iframe: (tagName, attribs) => ({
      tagName,
      attribs: { ...attribs, loading: 'lazy', referrerpolicy: 'strict-origin-when-cross-origin' },
    }),
  },
}

export const sanitizeHtml = (html: unknown): string => {
  if (typeof html !== 'string' || !html) return ''
  return sanitize(html, OPTIONS)
}

/** Field hook: cleans the value before it is saved. */
export const sanitizeHtmlHook = ({ value }: { value?: unknown }) =>
  typeof value === 'string' ? sanitizeHtml(value) : value
