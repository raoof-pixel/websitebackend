import type { Field } from 'payload'

import { sanitizeHtmlHook } from '../utilities/sanitizeHtml'

/**
 * Imported WordPress articles keep their original HTML here, untouched.
 *
 * The importer also converts that HTML into the rich-text editor. Where the conversion could
 * lose something (inline images, embeds, tables, iframes), it ticks `useLegacyHtml`, which tells
 * the website to render the original HTML instead. As soon as an editor changes the article in
 * the rich-text editor, the box is unticked automatically (see posts hooks).
 */
export const legacyHtmlFields = (): Field[] => [
  {
    type: 'collapsible',
    label: 'Original WordPress HTML',
    admin: {
      initCollapsed: true,
      condition: (data) => Boolean(data?.legacyHtml),
    },
    fields: [
      {
        name: 'useLegacyHtml',
        type: 'checkbox',
        defaultValue: false,
        label: 'Show the original WordPress HTML on the website instead of the editor content',
      },
      {
        name: 'legacyHtml',
        type: 'code',
        admin: { language: 'html', description: 'Cleaned automatically on save: scripts, event handlers and unknown iframes are removed.' },
        hooks: { beforeChange: [sanitizeHtmlHook] },
      },
    ],
  },
]
