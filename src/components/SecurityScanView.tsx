import { DefaultTemplate } from '@payloadcms/next/templates'
import { Gutter } from '@payloadcms/ui'
import Link from 'next/link'
import { redirect } from 'next/navigation'
import React from 'react'

import { hasRole } from '../access'
import { SecurityScanner } from './SecurityScanner'

/**
 * Admin view at /admin/security ("Security scan"). Registered in payload.config.ts under
 * admin.components.views. Payload does not protect custom views by itself, so this checks
 * the login (redirects to the login page) and the Admin role before rendering anything.
 *
 * Props follow Payload's documented custom root view (AdminViewServerProps); typed loosely
 * here so a Payload minor upgrade that adds props can't break the build.
 */
type Props = {
  initPageResult?: any
  params?: any
  searchParams?: any
}

export const SecurityScanView = ({ initPageResult, params, searchParams }: Props) => {
  const req = initPageResult?.req
  const payload = req?.payload
  const routes = (payload?.config?.routes || {}) as { admin?: string; api?: string }
  const adminRoute = (routes.admin || '/admin').replace(/\/$/, '')
  const apiRoute = (routes.api || '/api').replace(/\/$/, '')
  const user = req?.user || null

  if (!user) {
    redirect(`${adminRoute}/login?redirect=${encodeURIComponent(`${adminRoute}/security`)}`)
  }

  const templateProps = {
    i18n: req?.i18n,
    locale: initPageResult?.locale,
    params,
    payload,
    permissions: initPageResult?.permissions,
    searchParams,
    user: user || undefined,
    visibleEntities: initPageResult?.visibleEntities,
  }

  const isAdmin = hasRole(user as never, 'admin')

  return (
    <DefaultTemplate {...(templateProps as any)}>
      <Gutter>
        {isAdmin ? (
          <SecurityScanner apiRoute={apiRoute} adminRoute={adminRoute} />
        ) : (
          <section className="csme-sec">
            <div className="csme-sec__hero">
              <p className="csme-dash__eyebrow">Security</p>
              <h1 className="csme-sec__title">Admins only</h1>
              <p className="csme-sec__sub">The security scan can only be run by an administrator.</p>
              <div className="csme-dash__actions">
                <Link className="csme-btn csme-btn--lime" href={adminRoute}>
                  Back to dashboard
                </Link>
              </div>
            </div>
          </section>
        )}
      </Gutter>
    </DefaultTemplate>
  )
}

export default SecurityScanView
