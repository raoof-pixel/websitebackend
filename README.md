# CanadianSME CMS (backend)

The content backend that will replace WordPress for canadiansme.ca: an admin panel where the team
writes, edits and publishes articles, plus an API the new public website reads from.

Built on [Payload CMS 3](https://payloadcms.com) (Next.js) with a Neon Postgres database.

> **The live WordPress site is never changed by this project.** The importer only *reads* from
> WordPress. Nothing points at this backend until you decide to switch.

## What's inside

| Area | What it is |
| --- | --- |
| **Articles** (`posts`) | Title, slug, excerpt, featured image, rich-text body, categories + primary category, tags, authors, featured / editor's pick / sponsored flags, source URL, related articles, reading time. Drafts, autosave, revision history and **scheduled publishing**. |
| **Pages** | About, Advertise, Contact, etc. |
| **Categories / Tags / Authors** | Public taxonomies and bylines (`/category/x/`, `/tag/x/`, `/author/x/`). |
| **Media** | Image library with alt text, caption, credit, focal point and resized versions. Stored in Vercel Blob in production. |
| **SEO** | Every article/page/category has an SEO tab: meta title, description, share image, canonical URL, noindex. |
| **Redirects** | Manage 301/302 redirects from the admin. |
| **Settings** | Site name, logo, social links, SEO defaults, header/footer menus. |
| **Users & roles** | Admin, Editor (all articles), Author (own articles only), Automation (API key for scripts like the Newswire workflow; drafts only by default). |
| **Security** | Login lockout, strong passwords, HTML cleaning, upload restrictions, security headers and a tamper-proof activity log. See [SECURITY.md](SECURITY.md). |

URLs match WordPress exactly (`https://canadiansme.ca/<post-slug>/`), so Google rankings are kept.

## Run it locally

Requires Node 22.23+ (or 24) and pnpm.

```bash
cp .env.example .env      # fill in DATABASE_URL (Neon "dev" branch) and PAYLOAD_SECRET
pnpm install
pnpm dev                  # open http://localhost:3000/admin and create the first user (becomes Admin)
```

Create the database tables with `pnpm migrate` (also after pulling changes that add migrations).

## Import from WordPress (read-only)

```bash
pnpm import:wp --limit=100      # test: categories, tags, authors + newest 100 articles
pnpm import:wp                  # full import (all ~8,750 articles + pages); can take a few hours
pnpm import:wp --only=posts --since=2026-10-20   # catch up on recent changes
pnpm import:wp --skip-media     # quick run without downloading images
```

- It only sends GET requests to WordPress and downloads image files. It never writes to WordPress.
- Safe to re-run: records are matched by WordPress ID and updated, never duplicated.
- Published content is public via the REST API. To also copy drafts, add a WordPress
  Application Password in `.env` (`WP_USERNAME`, `WP_APP_PASSWORD`).
- SEO titles/descriptions from All in One SEO are carried over.
- Author bylines come from `src/data/wp-authors.json` (public name, slug and website of the 447 WordPress
  authors, no emails), because the site's user list isn't public.
- Raw HTML is cleaned on import, so scripts or spam links injected into old posts are not copied over.
- Each article keeps its original WordPress HTML. If it contains things the editor can't show 1:1
  (inline images, embeds, tables), the "Show the original WordPress HTML" box is ticked so the website
  renders it exactly as today. Editing the article in the editor switches it over automatically.

## API for the website

REST lives at `/api`, GraphQL at `/api/graphql`. Published content is public; drafts need a login or API key.

| Need | Request |
| --- | --- |
| What's at a URL (post, page, category, tag, author, redirect) | `GET /api/resolve?path=/some-slug/` |
| Latest articles | `GET /api/posts?sort=-publishedAt&limit=12&depth=1` |
| Articles in a category | `GET /api/posts?where[categories][in]=<id>&sort=-publishedAt` |
| Sitemap data | `GET /api/posts?select[slug]=true&select[updatedAt]=true&limit=1000&page=1` |
| Settings / menus | `GET /api/globals/site-settings`, `GET /api/globals/navigation` |
| Health check | `GET /api/health` |

Article bodies come as Lexical JSON (`content`); render them with
`@payloadcms/richtext-lexical/react` (`<RichText data={doc.content} />`). If `useLegacyHtml` is true,
render `legacyHtml` instead.

**Cache refresh:** when content is published/changed, the CMS POSTs
`{ collection, event, paths, tags, slug }` to `FRONTEND_REVALIDATE_URL` with header
`x-revalidate-secret`. The website's endpoint calls `revalidatePath`/`revalidateTag`.

**Previews:** the admin's "Preview" button opens
`<website>/api/preview?secret=PREVIEW_SECRET&path=/slug/` so the website can enable draft mode.

**Automation (Newswire):** create a user with the *Automation* role, enable its API key, then
`POST /api/posts` with header `Authorization: users API-Key <key>`.

## Deploy (Vercel + Neon)

1. Create a Neon project; use the pooled connection string as `DATABASE_URL` (production = `main` branch).
2. Import this repo in Vercel, add the env vars from `.env.example`, and add a Vercel Blob store
   (sets `BLOB_READ_WRITE_TOKEN`).
3. The initial database migration is already in `src/migrations`. The Vercel build (`pnpm run ci`) runs
   migrations, then builds. After changing collections, run `pnpm migrate:create <name>` and commit it.
4. Scheduled publishing runs via the Vercel Cron in `vercel.json` (needs `CRON_SECRET`). It is set to once a
   day so it works on Vercel's free plan; on Vercel Pro change the schedule to `*/5 * * * *` for 5-minute precision.

## Automated tests

Every push to `main` runs `.github/workflows/ci.yml` on GitHub: install, dependency audit, type-check,
database migration, production build, 29 security and function tests (`tests/smoke.mjs`), and a
read-only test import of the 15 newest WordPress articles. Results are published to the `ci-results` branch.
