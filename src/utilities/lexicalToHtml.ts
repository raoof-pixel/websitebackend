/**
 * Turns the rich-text editor's content (Lexical JSON) into HTML.
 * Same logic as the website's renderer (canadiansme-website/src/lexical.mjs), so a draft
 * preview looks exactly like the published article. No dependencies.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

const esc = (s: unknown = '') =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')

const safeUrl = (u: unknown = '') => {
  const s = String(u ?? '').trim()
  return /^(https?:\/\/|mailto:|tel:|\/|#)/i.test(s) ? s : '#'
}

const FORMATS: [number, string][] = [
  [1, 'strong'],
  [2, 'em'],
  [4, 's'],
  [8, 'u'],
  [16, 'code'],
  [32, 'sub'],
  [64, 'sup'],
]

const text = (n: any) => {
  let out = esc(n.text || '')
  for (const [bit, tag] of FORMATS) if ((n.format || 0) & bit) out = `<${tag}>${out}</${tag}>`
  return out
}

const align = (n: any) =>
  ['center', 'right', 'justify'].includes(n.format) ? ` style="text-align:${n.format}"` : ''

const mediaUrl = (m: any) => {
  if (!m || typeof m !== 'object') return ''
  return m.wpUrl || m.sizes?.large?.url || m.url || ''
}

const embed = (url: string, caption?: string) => {
  const u = safeUrl(url)
  let src = ''
  const yt = u.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([\w-]{6,})/)
  const vimeo = u.match(/vimeo\.com\/(\d+)/)
  if (yt) src = `https://www.youtube-nocookie.com/embed/${yt[1]}`
  else if (vimeo) src = `https://player.vimeo.com/video/${vimeo[1]}`
  const inner = src
    ? `<div class="embed"><iframe src="${src}" loading="lazy" allowfullscreen title="${esc(caption || 'Video')}"></iframe></div>`
    : `<p><a href="${esc(u)}" target="_blank" rel="noopener">${esc(caption || u)}</a></p>`
  return `<figure class="wp-block-embed">${inner}${caption ? `<figcaption>${esc(caption)}</figcaption>` : ''}</figure>`
}

const block = (f: any = {}) => {
  switch (f.blockType) {
    case 'embed':
      return embed(f.url, f.caption)
    case 'html':
      return f.html || '' // cleaned when saved
    case 'callout':
      return `<aside class="callout callout--${esc(f.style || 'info')}"><p>${esc(f.text || '')}</p>${
        f.linkUrl ? `<p><a class="btn" href="${esc(safeUrl(f.linkUrl))}">${esc(f.linkLabel || 'Learn more')}</a></p>` : ''
      }</aside>`
    default:
      return ''
  }
}

export function lexicalToHtml(value: any): string {
  const root = value?.root
  if (!root) return ''
  const kids = (n: any): string => (n.children || []).map(node).join('')

  function node(n: any): string {
    switch (n.type) {
      case 'text':
        return text(n)
      case 'linebreak':
        return '<br>'
      case 'tab':
        return ' '
      case 'paragraph': {
        const inner = kids(n)
        return inner ? `<p${align(n)}>${inner}</p>` : ''
      }
      case 'heading': {
        const tag = /^h[1-6]$/.test(n.tag) ? (n.tag === 'h1' ? 'h2' : n.tag) : 'h2'
        return `<${tag}${align(n)}>${kids(n)}</${tag}>`
      }
      case 'quote':
        return `<blockquote>${kids(n)}</blockquote>`
      case 'list': {
        const tag = n.listType === 'number' ? 'ol' : 'ul'
        return `<${tag}>${kids(n)}</${tag}>`
      }
      case 'listitem':
        return `<li>${kids(n)}</li>`
      case 'link':
      case 'autolink': {
        const f = n.fields || {}
        let url = f.url
        if (f.linkType === 'internal' && f.doc?.value?.slug) url = `/${f.doc.value.slug}/`
        const nt = f.newTab ? ' target="_blank" rel="noopener"' : ''
        return `<a href="${esc(safeUrl(url))}"${nt}>${kids(n)}</a>`
      }
      case 'horizontalrule':
        return '<hr>'
      case 'upload': {
        const src = mediaUrl(n.value)
        if (!src) return ''
        const cap = n.value?.caption || ''
        return `<figure class="wp-block-image"><img src="${esc(src)}" alt="${esc(n.value?.alt || '')}" loading="lazy" decoding="async">${
          cap ? `<figcaption>${esc(cap)}</figcaption>` : ''
        }</figure>`
      }
      case 'block':
        return block(n.fields)
      default:
        return kids(n)
    }
  }

  return kids(root)
}
