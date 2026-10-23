import path from 'path'
import type { CollectionConfig } from 'payload'
import { fileURLToPath } from 'url'

import { anyone, canCreateContent, canEditOwnOrAll } from '../access'
import { wpId } from '../fields/wordpress'

const filename = fileURLToPath(import.meta.url)
const dirname = path.dirname(filename)

/**
 * Images and files. In production files are stored in Vercel Blob (see payload.config.ts);
 * locally they go to /public/media.
 */
export const Media: CollectionConfig = {
  slug: 'media',
  admin: {
    group: 'Content',
    defaultColumns: ['filename', 'alt', 'createdAt'],
  },
  access: {
    read: anyone,
    create: canCreateContent,
    update: canEditOwnOrAll,
    delete: canEditOwnOrAll,
  },
  fields: [
    {
      name: 'alt',
      type: 'text',
      admin: { description: 'Describe the image for screen readers and Google Images.' },
    },
    { name: 'caption', type: 'text' },
    { name: 'credit', type: 'text', admin: { description: 'e.g. "Image courtesy: Canva"' } },
    {
      name: 'createdBy',
      type: 'relationship',
      relationTo: 'users',
      admin: { position: 'sidebar', readOnly: true },
      hooks: {
        beforeChange: [
          ({ operation, req, value }) =>
            operation === 'create' && req.user && !value ? req.user.id : value,
        ],
      },
    },
    wpId(),
    {
      name: 'wpUrl',
      type: 'text',
      index: true,
      label: 'Original WordPress URL',
      admin: { position: 'sidebar', readOnly: true },
    },
  ],
  upload: {
    staticDir: path.resolve(dirname, '../../public/media'),
    adminThumbnail: 'thumbnail',
    focalPoint: true,
    mimeTypes: ['image/*', 'application/pdf', 'video/mp4'],
    imageSizes: [
      { name: 'thumbnail', width: 300, height: 200, position: 'centre' },
      { name: 'card', width: 640 },
      { name: 'large', width: 1280 },
      { name: 'og', width: 1200, height: 630, position: 'centre' },
    ],
  },
}
