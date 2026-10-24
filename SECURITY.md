# Security

WordPress sites usually get hacked through vulnerable plugins and themes, weak or reused admin
passwords, unlimited login attempts, uploads that let attackers put executable files on the server,
and injected scripts or spam links in post content. This CMS is built to close each of those.

## Built in

| Risk | Protection |
| --- | --- |
| Vulnerable plugins/themes | No plugin marketplace. Every dependency is pinned to an exact version in `package.json`; run `pnpm audit` before each deploy. |
| Server takeover through uploads | Files are stored in Vercel Blob, not on a server that runs code. Only JPEG, PNG, WebP, GIF, AVIF and PDF are accepted (no SVG, which can carry scripts). 15 MB limit, safe file names. |
| Password guessing | Accounts lock for 30 minutes after 5 wrong passwords. Passwords must be 12+ characters with upper/lower case, a number and a symbol, and can't be common words. |
| Stolen sessions | Login cookie is HttpOnly, Secure and SameSite. Sessions expire after 8 hours and are stored server-side, so they can be revoked. Reset links expire after 30 minutes. |
| Self-registration / privilege escalation | Only admins can create users or change roles. The last admin can't be demoted. |
| Leaked API key | Automation (API-key) users can't log in to the admin, can't delete anything and by default can only save drafts for review (`AUTOMATION_CAN_PUBLISH`). Authors can only edit their own articles. |
| Malicious HTML (XSS, spam links) | All raw HTML (imported WordPress content, Custom HTML blocks, the article footer) is cleaned with sanitize-html (an allow-list cleaner) on save: scripts, event handlers, `javascript:` links, forms and iframes from unknown sites are removed. This also strips anything injected into the old WordPress database during past hacks. |
| Covering tracks | An **Activity log** records logins, failed logins (with IP) and every create, publish, update and delete. Entries can't be edited or deleted, not even by admins. |
| Clickjacking, sniffing, etc. | Security headers on every response: `X-Frame-Options: DENY`, `frame-ancestors 'none'`, HSTS, `nosniff`, `Referrer-Policy`, `Permissions-Policy`. The CMS is `noindex`. |
| API abuse | GraphQL playground and introspection off in production, query complexity and relationship depth capped, drafts hidden from the public. CORS and CSRF restricted to your own domains. |
| Weak secret | The app refuses to start in production unless `PAYLOAD_SECRET` is at least 32 random characters. |
| Scheduled-publish endpoint | Requires `CRON_SECRET`. |
| Leftovers of old hacks | The **Security scanner** (Admin → Security scan) checks every imported article, page, taxonomy, author, upload, user, redirect and setting for injected code, hidden spam and rogue accounts. See below. |
| Leaked secrets / vulnerable packages | The **Security** GitHub workflow scans the git history for committed keys (gitleaks), audits dependencies and runs weekly. |
| Data loss | Every article and page keeps up to 25 revisions. Neon keeps point-in-time restore of the database. |

## Do this when going live

1. **Turn on 2-factor login** for every account that can reach this system: GitHub, Vercel, Neon,
   your domain registrar and email. Those accounts are the real keys to the site.
2. In Vercel, enable the **Firewall** with Bot Protection and add a **rate-limit rule** for
   `/api/users/login` and `/api/users/forgot-password` (for example 10 requests per minute per IP).
3. Optional extra lock: put the admin behind **Cloudflare Access** or Vercel's password protection
   so `/admin` is only reachable by your team, even before the Payload login screen.
4. Generate secrets with `openssl rand -hex 32` (or a password manager). Never reuse WordPress passwords.
5. Give people the lowest role they need. Create one Automation user per script, and delete its API
   key if the script is retired.
6. Check **Admin → Activity log** weekly for failed logins and unexpected changes, and run
   **Admin → Security scan** after every WordPress import and once a month.
7. Run `pnpm audit` and update Payload (`pnpm up "@payloadcms/*" payload`) monthly.

## Security scanner

The old WordPress site was hacked several times, and about 8,800 articles were imported from its
database. The HTML cleaner removes scripts and unknown iframes whenever content is *saved*, but
anything imported before the cleaner existed, or written straight into the database, is not
re-checked, and spam links are ordinary `<a href>` links that no HTML cleaner removes. The scanner
finds what is left.

It is **read-only** (it never changes a document), **admin-only** and **stateless** (results are
not stored; download them if you want to keep them).

### How to run it

- **In the admin:** sidebar → *Security* → **Security scan** (or the *Security scan* button on the
  dashboard), choose what to scan, press **Start scan**. It works through everything page by page
  (25 articles per request, so it never hits Vercel's time limit) with a progress bar. Expect a
  few minutes for all articles. You can stop at any time; partial results stay on screen.
- **API:** `POST /api/security-scan` with an admin login cookie or an admin API key, body
  `{ "target": "posts", "page": 1, "perPage": 25 }`. Targets: `posts`, `pages`, `categories`,
  `tags`, `authors`, `media`, `users`, `redirects`, `settings`. Returns
  `{ target, page, perPage, totalPages, totalDocs, scanned, findings, durationMs }`; call again with
  `page + 1` until `page == totalPages`. Anonymous → 401, other roles (including Automation keys) → 403.
- **Command line / CI:** `pnpm security:scan` (uses `DATABASE_URL`) writes
  `ci-output/security-scan.json` and `.md`. Options: `--only=posts,users`, `--fail-on=critical`,
  `--out=folder`. CI runs it against the test database after the smoke tests and adds the summary
  to the job page.

Starting and finishing a scan is recorded in the Activity log ("Security scan started/finished").

### What it checks

All rules live in `src/security/rules.ts` (plain functions with unit tests in
`tests/security-rules.test.mjs`); the admin view's **What is checked?** button lists them.

| Where | Checks |
| --- | --- |
| Articles & pages: original WordPress HTML, rich-text content (links, Custom HTML and Embed blocks), excerpt, SEO title/description/canonical URL, source URL | `<script>` tags, `on…=` event handlers, `javascript:`/`vbscript:`/`data:` URLs (also entity-encoded), iframes/embeds/objects from hosts not on the cleaner's allow-list (`src/utilities/iframeHosts.ts`), forms, `<style>`/`<base>`/`<meta>` tags, content hidden with CSS (`display:none`, `font-size:0`, off-screen, zero height, `opacity:0`) that contains links or spam, obfuscated JavaScript (`eval`, `atob`, `String.fromCharCode`, `document.write`, `unescape`, `\x41…`, `_0x1a2b`), JS and meta-refresh redirects, long base64 and encoded strings, spam links (pharma, casino/betting, payday loans, adult, crypto scams, essay mills, replicas, bought followers/backlinks), spam keyword clusters, links to spam-heavy TLDs (`.ru`, `.cn`, `.top`, `.xyz`, `.click`, `.loan`, `.work`, `.bid`, …), URL shorteners, raw IP addresses, link text showing a different domain than the target, more than 40 external links, canonical URL pointing to another site |
| Categories, tags, authors | Spam words and links in names, slugs and descriptions/bios (any spam phrase in a short field counts); author profile links that are `http://`, suspicious, or not on the expected network |
| Images & files | Dangerous extensions (`.php`, `.phtml`, `.js`, `.html`, `.svg`, `.exe`, …), double extensions (`shell.php.jpg`), file type not matching the name, file types other than images/PDF, original WordPress URL outside canadiansme.ca (Jetpack's `i0.wp.com/canadiansme.ca/…` is fine) |
| Users & logins | Every admin listed for review, more than 3 admins, admins created in the last 30 days, Automation accounts with extra roles, API keys on staff accounts, accounts older than 30 days that never logged in, locked accounts, throw-away email domains, 5+ failed logins for one email or 10+ from one IP in the last 7 days (from the Activity log). Password hashes, salts, tokens and API keys are never returned. |
| Redirects | Redirects to other websites (low), to suspicious domains, shorteners, IPs or `javascript:` (high), spam words in the "from" path |
| Site settings & menus | Injected HTML/scripts in the article footer, organisation JSON-LD and text fields, social links that don't go to the right network or use `http://`, suspicious contact email, suspicious menu links |

### How to read the results

- **Critical**: almost certainly malicious (scripts, `javascript:` links, redirects, executable
  uploads). Fix now.
- **High**: very likely spam or an attack (hidden links, spam links, untrusted iframes, obfuscated
  code, mixed-role bots, brute-force IPs). Review today.
- **Medium**: suspicious, often spam but sometimes legitimate (suspicious TLDs, keyword clusters,
  link floods, offsite media, many admins).
- **Low**: worth a look (shortened links, `http://` profile links, hidden accordion text, admin list).

Each row shows the item, the field, the rule and a short excerpt (shown as plain text, never as
HTML). Click the item to open it in a new tab. Filter by severity, rule or collection, or search;
**Download JSON** saves everything, **Download CSV** saves the filtered rows (cells are protected
against spreadsheet formula injection).

**Fixing:** open the item and remove the spam. For imported articles, edit *Original WordPress
HTML* (saving runs the cleaner again, which also strips scripts and hidden styles), or untick it
and use the editor. Delete unknown admin users, rogue redirects and dangerous uploads. If you find
critical items, also rotate secrets (`PAYLOAD_SECRET`, API keys, database password) in case they
were exposed on the old site.

### False positives

The scanner is tuned to keep noise low (spam words only count inside links, in clusters, or in
short fields; text typed in the editor that *mentions* `<script>` is not treated as code; press
release click-tracking links are not "cloaked"), but some findings will be harmless:

- Articles *about* online gambling, pharmacies or crypto scams can trigger a keyword cluster.
- Old embed codes (tweets, Instagram, forms) contain scripts or iframes from sites not on the
  allow-list. Replace them with an **Embed** block, or, if the site is trustworthy, add its host to
  `src/utilities/iframeHosts.ts` (that also lets the cleaner keep it).
- Round-up articles can have more than 40 external links; startups can use `.xyz` or `.top`.
- Accounts created before the Activity log existed show as "never logged in".

The scanner reads the saved (main) version of each document; unpublished drafts saved over a
published article are not included. The tag parser is heuristic (no full HTML parser), so it can
miss tricks a browser would still run; it is a review aid, not a replacement for the HTML cleaner.

### Code scanning

`.github/workflows/security.yml` runs on every push to `main`, every Monday and on demand:
gitleaks (whole git history; set a `GITLEAKS_LICENSE` secret only if the repo moves to a GitHub
organisation), a pattern-based secrets grep as a fallback, `pnpm audit --prod` (fails on
high/critical and lists them in the job summary) and the scanner rule tests. `ci.yml` also shows
the audit summary on every run, without failing the build.

