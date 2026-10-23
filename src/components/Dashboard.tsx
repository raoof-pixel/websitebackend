import Link from 'next/link'
import type { Payload } from 'payload'
import React from 'react'

type Props = { payload?: Payload; user?: { name?: string | null; email?: string; roles?: string[] } | null }

const count = async (payload: Payload, collection: any, where?: any) => {
  try {
    const r = await payload.count({ collection, where, overrideAccess: true })
    return r.totalDocs
  } catch {
    return 0
  }
}

/** Welcome banner with live numbers and shortcuts, shown at the top of the dashboard. */
export const Dashboard = async ({ payload, user }: Props) => {
  const first = (user?.name || user?.email || 'there').split(' ')[0]
  const isAdmin = Array.isArray(user?.roles) && user!.roles!.includes('admin')
  const [published, drafts, authors, media] = payload
    ? await Promise.all([
        count(payload, 'posts', { _status: { equals: 'published' } }),
        count(payload, 'posts', { _status: { equals: 'draft' } }),
        count(payload, 'authors'),
        count(payload, 'media'),
      ])
    : [0, 0, 0, 0]
  const hour = new Date().getUTCHours() - 4 // Toronto time, roughly
  const greeting = hour < 12 && hour >= 0 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening'
  const fmt = (n: number) => n.toLocaleString('en-CA')

  const stats = [
    { label: 'Published articles', value: fmt(published), href: '/admin/collections/posts?where[_status][equals]=published', tone: 'lime' },
    { label: 'Drafts waiting', value: fmt(drafts), href: '/admin/collections/posts?where[_status][equals]=draft', tone: 'violet' },
    { label: 'Authors', value: fmt(authors), href: '/admin/collections/authors', tone: 'sky' },
    { label: 'Images & files', value: fmt(media), href: '/admin/collections/media', tone: 'coral' },
  ]

  return (
    <section className="csme-dash">
      <div className="csme-dash__hero">
        <div>
          <p className="csme-dash__eyebrow">CanadianSME Newsroom</p>
          <h1 className="csme-dash__title">
            {greeting}, <span>{first}</span>
          </h1>
          <p className="csme-dash__sub">Write, edit and publish stories for Canada&apos;s small business community.</p>
        </div>
        <div className="csme-dash__actions">
          <Link className="csme-btn csme-btn--lime" href="/admin/collections/posts/create">
            + New article
          </Link>
          <Link className="csme-btn csme-btn--ghost" href="/admin/collections/media/create">
            Upload image
          </Link>
          {isAdmin && (
            <Link className="csme-btn csme-btn--ghost" href="/admin/collections/audit-logs">
              Activity log
            </Link>
          )}
        </div>
      </div>
      <div className="csme-dash__stats">
        {stats.map((s) => (
          <Link key={s.label} href={s.href} className={`csme-stat csme-stat--${s.tone}`}>
            <span className="csme-stat__value">{s.value}</span>
            <span className="csme-stat__label">{s.label}</span>
          </Link>
        ))}
      </div>
    </section>
  )
}

export default Dashboard
