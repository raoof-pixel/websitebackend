import type { Field } from 'payload'

/**
 * The original WordPress ID. The importer uses it to update records instead of duplicating
 * them, so the import can be re-run safely at any time.
 */
export const wpId = (): Field => ({
  name: 'wpId',
  type: 'number',
  index: true,
  unique: true,
  label: 'WordPress ID',
  admin: {
    position: 'sidebar',
    readOnly: true,
    description: 'Set by the WordPress import. Leave empty for new content.',
  },
})
