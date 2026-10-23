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
| Malicious HTML (XSS, spam links) | All raw HTML (imported WordPress content, Custom HTML blocks, the article footer) is cleaned with DOMPurify on save: scripts, event handlers, `javascript:` links, forms and iframes from unknown sites are removed. This also strips anything injected into the old WordPress database during past hacks. |
| Covering tracks | An **Activity log** records logins, failed logins (with IP) and every create, publish, update and delete. Entries can't be edited or deleted, not even by admins. |
| Clickjacking, sniffing, etc. | Security headers on every response: `X-Frame-Options: DENY`, `frame-ancestors 'none'`, HSTS, `nosniff`, `Referrer-Policy`, `Permissions-Policy`. The CMS is `noindex`. |
| API abuse | GraphQL playground and introspection off in production, query complexity and relationship depth capped, drafts hidden from the public. CORS and CSRF restricted to your own domains. |
| Weak secret | The app refuses to start in production unless `PAYLOAD_SECRET` is at least 32 random characters. |
| Scheduled-publish endpoint | Requires `CRON_SECRET`. |
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
6. Check **Admin → Activity log** weekly for failed logins and unexpected changes.
7. Run `pnpm audit` and update Payload (`pnpm up "@payloadcms/*" payload`) monthly.
