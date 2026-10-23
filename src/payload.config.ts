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
import { AuditLogs } from './collections/AuditLogs'
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

// Refuse to start in production with a weak or missing secret (it signs every login).
const secret = process.env.PAYLOAD_SECRET || ''
if (process.env.NODE_ENV === 'production' && process.env.NEXT_PHASE !== 'phase-production-build' && secret.length < 32) {
  throw new Error('PAYLOAD_SECRET must be set to a random string of at least 32 characters.')
}

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
  collections: [Posts, Pages, Categories, Tags, Authors, Media, Users, AuditLogs],
  globals: [SiteSettings, Navigation],
  editor: lexicalEditor(),
  secret,
  typescript: { outputFile: path.resolve(dirname, 'payload-types.ts') },
  db: postgresAdapter({
    pool: { connectionString: process.env.DATABASE_URL || '' },
  }),
  sharp,
  cors: allowedOrigins,
  csrf: allowedOrigins,
  // Limit how deep a single API request can pull related data (stops expensive abuse).
  maxDepth: 4,
  defaultDepth: 1,
  graphQL: {
    disablePlaygroundInProduction: true,
    disableIntrospectionInProduction: true,
    maxComplexity: 1000,
  },
  upload: {
    limits: { fileSize: 15 * 1024 * 1024 }, // 15 MB per file
    abortOnLimit: true,
    safeFileNames: true,
  },
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
