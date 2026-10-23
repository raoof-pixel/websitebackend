import type { Block } from 'payload'

import {
  BlocksFeature,
  FixedToolbarFeature,
  HeadingFeature,
  HorizontalRuleFeature,
  lexicalEditor,
} from '@payloadcms/richtext-lexical'

import { sanitizeHtmlHook } from '../utilities/sanitizeHtml'

/** Embed a YouTube/Vimeo video, a podcast, a social post, etc. by URL. */
export const EmbedBlock: Block = {
  slug: 'embed',
  interfaceName: 'EmbedBlock',
  labels: { singular: 'Embed (video, social post)', plural: 'Embeds' },
  fields: [
    {
      name: 'url',
      type: 'text',
      required: true,
      admin: { description: 'e.g. https://www.youtube.com/watch?v=...' },
      validate: (v: unknown) =>
        typeof v === 'string' && /^https:\/\/[^\s]+$/i.test(v) ? true : 'Must be an https:// link',
    },
    { name: 'caption', type: 'text' },
  ],
}

/** Paste raw HTML (newsletter forms, iframes, tables) when the editor can't express it. */
export const HtmlBlock: Block = {
  slug: 'html',
  interfaceName: 'HtmlBlock',
  labels: { singular: 'Custom HTML', plural: 'Custom HTML' },
  fields: [
    {
      name: 'html',
      type: 'code',
      required: true,
      admin: {
        language: 'html',
        description: 'Scripts and iframes from unknown sites are removed automatically when saved.',
      },
      hooks: { beforeChange: [sanitizeHtmlHook] },
    },
  ],
}

/** Call-to-action box, e.g. "Subscribe to the magazine". */
export const CalloutBlock: Block = {
  slug: 'callout',
  interfaceName: 'CalloutBlock',
  labels: { singular: 'Callout box', plural: 'Callout boxes' },
  fields: [
    {
      name: 'style',
      type: 'select',
      defaultValue: 'info',
      options: [
        { label: 'Info', value: 'info' },
        { label: 'Highlight', value: 'highlight' },
        { label: 'Disclaimer', value: 'disclaimer' },
      ],
    },
    { name: 'text', type: 'textarea', required: true },
    { name: 'linkLabel', type: 'text' },
    {
      name: 'linkUrl',
      type: 'text',
      validate: (v: unknown) =>
        !v || (typeof v === 'string' && /^(https:\/\/|\/|mailto:)/i.test(v)) ? true : 'Use https://, a /path or mailto:',
    },
  ],
}

/** The editor used for article and page bodies. */
export const articleEditor = lexicalEditor({
  features: ({ rootFeatures }) => [
    ...rootFeatures,
    HeadingFeature({ enabledHeadingSizes: ['h2', 'h3', 'h4', 'h5', 'h6'] }),
    HorizontalRuleFeature(),
    FixedToolbarFeature(),
    BlocksFeature({ blocks: [EmbedBlock, HtmlBlock, CalloutBlock] }),
  ],
})
