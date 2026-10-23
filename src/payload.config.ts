import { postgresAdapter } from '@payloadcms/db-postgres'
import { redirectsPlugin } from '@payloadcms/plugin-redirects'
import { seoPlugin } from '@payloadcms/plugin-seo'
import { lexicalEditor } from '@payloadcms/richtext-lexical'
import { vercelBlobStorage } from '@payloadcms/storage-vercel-blob'
import path from 'path'
import { buildConfig } from 'payload'
import type { PayloadRequest } from 'payload'
import sharp from 'sharp'
import { fileURLToPath } from 'url'

import { isStaff } from './access'
import { Authors } from './collections/Authors'
import { Categories } from './collections/Categories'
import { Media } from './collections/Media'
import { Pages } from './collections/Pages'
import { Posts } from './collections/Posts'
import { Tags } from './collections/Tags'
import { Users } from './collections/Users'
import { healthEndpoint, resolveEndpoint } from './endpoints/resolve'
import { Navigation, SiteSettings } from './globals/SiteSettings'
import { getServerURL, getSiteURL } from './utilities/revalidate'

const filename = fileURLToPath(import.meta.url)
const dirname = path.dirname(filename)

/** Origins allowed to call the API from a browser (the public website, previews). */
const allowedOrigins = [
  getServerURL(),
  getSiteURL(),
  ...(process.env.CORS_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
]

export default buildConfig({
  serverURL: process.env.NEXT_PUBLIC_SERVER_URL || undefined,
  admin: {
    user: Users.slug,
    importMap: { baseDir: path.resolve(dirname) },
    meta: { titleSuffix: ' - CanadianSME CMS' },
  },
  collections: [Posts, Pages, Categories, Tags, Authors, Media, Users],
  globals: [SiteSettings, Navigation],
  editor: lexicalEditor(),
  secret: process.env.PAYLOAD_SECRET || '',
  typescript: { outputFile: path.resolve(dirname, 'payload-types.ts') },
  db: postgresAdapter({
    pool: { connectionString: process.env.DATABASE_URL || '' },
  }),
  sharp,
  cors: allowedOrigins,
  csrf: allowedOrigins,
  endpoints: [resolveEndpoint, healthEndpoint],
  plugins: [
    seoPlugin({
      collections: ['posts', 'pages', 'categories'],
      uploadsCollection: 'media',
      tabbedUI: true,
      generateTitle: ({ doc }) => (doc as { title?: string })?.title || '',
      generateDescription: ({ doc }) => (doc as { excerpt?: string })?.excerpt || '',
      generateURL: ({ doc }) => {
        const s = (doc as { slug?: string })?.slug
        return s ? `${getSiteURL()}/${s}/` : getSiteURL()
      },
      fields: ({ defaultFields }) => [
        ...defaultFields,
        {
          name: 'canonicalUrl',
          type: 'text',
          admin: { description: 'Leave empty to use the article URL.' },
        },
        {
          name: 'noIndex',
          type: 'checkbox',
          label: 'Hide from Google (noindex)',
        },
      ],
    }),
    redirectsPlugin({
      collections: ['posts', 'pages'],
      redirectTypes: ['301', '302'],
      overrides: {
        admin: { group: 'Settings' },
        access: { read: () => true, create: isStaff, update: isStaff, delete: isStaff },
      },
    }),
    vercelBlobStorage({
      enabled: Boolean(process.env.BLOB_READ_WRITE_TOKEN),
      collections: { media: true },
      token: process.env.BLOB_READ_WRITE_TOKEN,
    }),
  ],
  jobs: {
    // Scheduled publishing. On Vercel, a cron calls /api/payload-jobs/run (see vercel.json).
    access: {
      run: ({ req }: { req: PayloadRequest }): boolean => {
        if (req.user) return true
        const secret = process.env.CRON_SECRET
        if (!secret) return false
        return req.headers.get('authorization') === `Bearer ${secret}`
      },
    },
    tasks: [],
  },
})
