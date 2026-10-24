'use client'

import { useAuth, useConfig } from '@payloadcms/ui'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import React from 'react'

/** "Security scan" link at the bottom of the admin navigation, shown to admins only. */
export const SecurityNavLink = () => {
  const { user } = useAuth()
  const { config } = useConfig()
  const pathname = usePathname()
  const roles = ((user as { roles?: string[] } | null | undefined)?.roles || []) as string[]
  if (!roles.includes('admin')) return null

  const adminRoute = ((config as { routes?: { admin?: string } })?.routes?.admin || '/admin').replace(/\/$/, '')
  const href = `${adminRoute}/security`
  const active = pathname === href || pathname?.startsWith(`${href}/`)

  return (
    <div className="csme-nav-extra">
      <span className="nav-group__label csme-nav-extra__label">Security</span>
      <Link href={href} className={`nav__link csme-nav-extra__link${active ? ' active' : ''}`} prefetch={false}>
        {active ? <div className="nav__link-indicator" /> : null}
        <span className="nav__link-label">Security scan</span>
      </Link>
    </div>
  )
}

export default SecurityNavLink
