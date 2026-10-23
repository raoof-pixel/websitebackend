import { slugField } from 'payload'

type Slugify = NonNullable<NonNullable<Parameters<typeof slugField>[0]>['slugify']>

/**
 * Turns a title into a URL slug: "Hello, Cafe World!" -> "hello-cafe-world".
 */
export const toSlug = (value: unknown): string =>
  String(value ?? '')
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .replace(/&[a-z]+;/gi, ' ')
    .replace(/['`"\p{Pi}\p{Pf}]/gu, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 200)

/**
 * When `req.context.preserveSlug` is true (the WordPress importer sets it), slugs are kept
 * exactly as given so every existing canadiansme.ca URL stays identical.
 */
const slugify: Slugify = ({ req, valueToSlugify }) => {
  if (req?.context?.preserveSlug && typeof valueToSlugify === 'string' && valueToSlugify) {
    return valueToSlugify
  }
  return toSlug(valueToSlugify) || undefined
}

export const slug = (useAsSlug = 'title') =>
  slugField({
    useAsSlug,
    slugify,
  })
