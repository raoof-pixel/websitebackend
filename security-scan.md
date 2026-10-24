# Security scan

Scanned: posts 5, pages 0, categories 1, tags 0, authors 447, media 1, users 4, redirects 1, settings 2

| Severity | Findings |
| --- | ---: |
| critical | 1 |
| high | 3 |
| medium | 4 |
| low | 1 |

## By rule

- **Script tag** (`script-tag`): 1
- **Iframe or embed from an unknown site** (`untrusted-embed`): 1
- **Spam link** (`spam-link`): 1
- **Link to a suspicious domain** (`suspicious-domain`): 1
- **Recently created admin** (`new-admin`): 1
- **Repeated failed logins** (`failed-logins`): 1
- **Admin account (review)** (`admin-account`): 1
- **Redirect to a suspicious address** (`suspicious-redirect`): 1
- **Spam words in a redirect path** (`spam-redirect-path`): 1

## Most severe (first 50)

- CRITICAL posts #5 "Scanner Seed Article" excerpt: script-tag — `<script>`
- HIGH posts #1 "Security Test Article" legacyHtml: untrusted-embed — `<iframe loading="lazy" referrerpolicy="strict-origin-when-cross-origin">`
- HIGH posts #5 "Scanner Seed Article" legacyHtml: spam-link — `buy viagra online → https://cheap-pills.xyz/viagra`
- HIGH redirects #1 "/cheap-viagra-online/" to.url: suspicious-redirect — `/cheap-viagra-online/ → https://bit.ly/abc123 (Shortened link)`
