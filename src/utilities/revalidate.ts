import type { PayloadRequest } from 'payload'

export type RevalidatePayload = {
  /** What changed, e.g. "posts", "pages", "categories", "settings". */
  collection: string
  /** Event type. */
  event: 'change' | 'delete'
  /** Public URL paths on the website that should be refreshed, e.g. ["/my-post/"]. */
  paths: string[]
  /** Cache tags the website can use with revalidateTag(), e.g. ["posts", "post:my-post"]. */
  tags: string[]
  id?: number | string
  slug?: string | null
}

/**
 * Tells the separate public website (built in parallel) that content changed, so it can
 * refresh its cache. Configure on the website side an endpoint that accepts this JSON.
 *
 *   FRONTEND_REVALIDATE_URL=https://canadiansme.ca/api/revalidate
 *   REVALIDATE_SECRET=<shared secret>  (sent as the x-revalidate-secret header)
 *
 * Never throws: a website that is down must not block editors from saving.
 * Skipped when req.context.disableRevalidate is true (bulk imports).
 */
export const notifyFrontend = async (req: PayloadRequest, body: RevalidatePayload) => {
  if (req.context?.disableRevalidate) return
  const url = process.env.FRONTEND_REVALIDATE_URL
  if (!url) return

  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 5000)
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-revalidate-secret': process.env.REVALIDATE_SECRET || '',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    })
    clearTimeout(timer)
    if (!res.ok) {
      req.payload.logger.warn(`Frontend revalidate returned ${res.status} for ${body.paths.join(', ')}`)
    }
  } catch (err) {
    req.payload.logger.warn(`Frontend revalidate failed: ${(err as Error).message}`)
  }
}

/** Public path helpers. These mirror the current WordPress permalink structure. */
export const paths = {
  post: (slug?: string | null) => (slug ? `/${slug}/` : null),
  page: (slug?: string | null) => (slug ? `/${slug}/` : null),
  category: (slug?: string | null) => (slug ? `/category/${slug}/` : null),
  tag: (slug?: string | null) => (slug ? `/tag/${slug}/` : null),
  author: (slug?: string | null) => (slug ? `/author/${slug}/` : null),
}

export const getSiteURL = () =>
  (process.env.NEXT_PUBLIC_SITE_URL || 'https://canadiansme.ca').replace(/\/$/, '')

/** Where this CMS runs. On Vercel the project's own address is detected automatically. */
export const getServerURL = () =>
  (
    process.env.NEXT_PUBLIC_SERVER_URL ||
    (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : '') ||
    'http://localhost:3000'
  ).replace(/\/$/, '')

/** This deployment's own address on Vercel (differs per deployment), if any. */
export const getDeploymentURL = () => (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : '')
