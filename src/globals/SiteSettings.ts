import type { Field, GlobalConfig } from 'payload'

import { anyone, isStaff } from '../access'
import { notifyFrontend } from '../utilities/revalidate'

const link = (name: string, label?: string): Field => ({
  name,
  type: 'array',
  label,
  fields: [
    {
      type: 'row',
      fields: [
        { name: 'label', type: 'text', required: true },
        {
          name: 'url',
          type: 'text',
          required: true,
          admin: { description: 'A path like /category/interviews/ or a full https:// link' },
        },
        { name: 'newTab', type: 'checkbox', label: 'Open in new tab' },
      ],
    },
    {
      name: 'children',
      type: 'array',
      label: 'Sub-menu',
      fields: [
        {
          type: 'row',
          fields: [
            { name: 'label', type: 'text', required: true },
            { name: 'url', type: 'text', required: true },
            { name: 'newTab', type: 'checkbox', label: 'Open in new tab' },
          ],
        },
      ],
    },
  ],
})

/** Site-wide settings the website reads: name, logo, social links, defaults for SEO. */
export const SiteSettings: GlobalConfig = {
  slug: 'site-settings',
  label: 'Site settings',
  admin: { group: 'Settings' },
  access: { read: anyone, update: isStaff },
  fields: [
    {
      type: 'tabs',
      tabs: [
        {
          label: 'General',
          fields: [
            { name: 'siteName', type: 'text', defaultValue: 'CanadianSME Small Business Magazine' },
            { name: 'tagline', type: 'text', defaultValue: 'Empowering Canadian Small and Medium Enterprises' },
            { name: 'logo', type: 'upload', relationTo: 'media' },
            { name: 'logoDark', type: 'upload', relationTo: 'media', label: 'Logo (dark backgrounds)' },
            { name: 'favicon', type: 'upload', relationTo: 'media' },
            { name: 'contactEmail', type: 'email', defaultValue: 'info@canadiansme.ca' },
            { name: 'subscribeUrl', type: 'text', defaultValue: '/subscription/' },
          ],
        },
        {
          label: 'SEO defaults',
          fields: [
            {
              name: 'titleSuffix',
              type: 'text',
              defaultValue: ' - CanadianSME Small Business Magazine',
              admin: { description: 'Appended to every page title.' },
            },
            { name: 'defaultDescription', type: 'textarea' },
            { name: 'defaultShareImage', type: 'upload', relationTo: 'media' },
            {
              name: 'organizationSchema',
              type: 'json',
              admin: { description: 'Optional JSON-LD Organization data the website can output.' },
            },
          ],
        },
        {
          label: 'Social',
          fields: [
            {
              name: 'social',
              type: 'group',
              fields: [
                { name: 'facebook', type: 'text', defaultValue: 'https://www.facebook.com/canadiansme' },
                { name: 'instagram', type: 'text', defaultValue: 'https://www.instagram.com/canadiansme/' },
                { name: 'x', type: 'text', label: 'X (Twitter)', defaultValue: 'https://twitter.com/canadian_sme' },
                {
                  name: 'linkedin',
                  type: 'text',
                  defaultValue: 'https://www.linkedin.com/company/canadiansme-business-magazine',
                },
                {
                  name: 'youtube',
                  type: 'text',
                  defaultValue: 'https://www.youtube.com/c/CanadianSMESmallBusinessMagazine',
                },
              ],
            },
          ],
        },
        {
          label: 'Article footer',
          fields: [
            {
              name: 'articleFooterHtml',
              type: 'code',
              admin: {
                language: 'html',
                description:
                  'Optional block (subscribe message, disclaimer) the website can show under every article.',
              },
            },
          ],
        },
      ],
    },
  ],
  hooks: {
    afterChange: [
      async ({ doc, req }) => {
        await notifyFrontend(req, {
          collection: 'site-settings',
          event: 'change',
          paths: ['/'],
          tags: ['site-settings'],
        })
        return doc
      },
    ],
  },
}

/** Header and footer menus. */
export const Navigation: GlobalConfig = {
  slug: 'navigation',
  admin: { group: 'Settings' },
  access: { read: anyone, update: isStaff },
  fields: [link('header', 'Header menu'), link('footer', 'Footer menu')],
  hooks: {
    afterChange: [
      async ({ doc, req }) => {
        await notifyFrontend(req, {
          collection: 'navigation',
          event: 'change',
          paths: ['/'],
          tags: ['navigation'],
        })
        return doc
      },
    ],
  },
}
