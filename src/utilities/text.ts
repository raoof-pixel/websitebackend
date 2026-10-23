/** Collects the plain text from a Lexical editor state (rich-text field value). */
export const lexicalToText = (value: unknown): string => {
  const out: string[] = []
  const walk = (node: any) => {
    if (!node || typeof node !== 'object') return
    if (typeof node.text === 'string') out.push(node.text)
    if (Array.isArray(node.children)) {
      node.children.forEach(walk)
      if (node.type === 'paragraph' || node.type === 'heading' || node.type === 'listitem') out.push(' ')
    }
  }
  walk((value as any)?.root)
  return out.join('').replace(/\s+/g, ' ').trim()
}

/** Strips tags from an HTML string. */
export const htmlToText = (html: unknown): string =>
  String(html ?? '')
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&#8217;|&rsquo;/g, "'")
    .replace(/&#8211;|&ndash;/g, '-')
    .replace(/&#8212;|&mdash;/g, '-')
    .replace(/&#8220;|&#8221;|&ldquo;|&rdquo;|&quot;/g, '"')
    .replace(/&hellip;|&#8230;/g, '...')
    .replace(/&[a-z0-9#]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim()

/** Minutes to read at ~230 words per minute (minimum 1). */
export const readingMinutes = (text: string): number => {
  const words = text ? text.split(/\s+/).filter(Boolean).length : 0
  return Math.max(1, Math.round(words / 230))
}
