/**
 * Command-line WordPress importer (READ-ONLY on WordPress). See src/import/wordpress.ts.
 *
 *   pnpm import:wp                 # everything
 *   pnpm import:wp --limit=100     # test run
 *   pnpm import:wp --only=posts --since=2026-10-01 --skip-existing --concurrency=8
 *
 * The same import can also be run from inside the CMS by an admin: POST /api/wp-import.
 */
import { getPayload } from 'payload'

import { runCli } from '../import/wordpress'
import config from '../payload.config'

try {
  const payload = await getPayload({ config })
  const counts = await runCli(payload)
  process.exit(counts.postErrors || counts.pageErrors ? 1 : 0)
} catch (err) {
  console.error(err)
  process.exit(1)
}
