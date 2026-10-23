'use client'

import { useDocumentInfo, useFormFields } from '@payloadcms/ui'
import React from 'react'

/** Sidebar buttons on an article: open the live page, or preview the draft in the site design. */
export const ViewOnSite = ({ siteURL }: { siteURL?: string }) => {
  const { id } = useDocumentInfo()
  const slug = useFormFields(([fields]) => fields?.slug?.value) as string | undefined
  const status = useFormFields(([fields]) => fields?._status?.value) as string | undefined
  if (!id) return null

  const live = status === 'published' && slug && siteURL ? `${siteURL}/${slug}/` : null
  return (
    <div className="csme-view-on-site">
      {live ? (
        <a className="csme-btn csme-btn--lime" href={live} target="_blank" rel="noopener noreferrer">
          View on website ↗
        </a>
      ) : (
        <p className="csme-view-on-site__note">Not on the website yet. Publish to make it live.</p>
      )}
      <a className="csme-btn csme-btn--outline" href={`/api/site-preview?collection=posts&id=${id}`} target="_blank" rel="noopener noreferrer">
        Preview draft ↗
      </a>
      {live ? <p className="csme-view-on-site__note">The website updates about 1–2 minutes after you publish.</p> : null}
    </div>
  )
}

export default ViewOnSite
