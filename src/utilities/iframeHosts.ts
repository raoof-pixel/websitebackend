/**
 * Hosts whose iframes are allowed in article HTML (videos, maps, podcasts, forms).
 *
 * Shared by the HTML cleaner (utilities/sanitizeHtml.ts) and the security scanner
 * (security/rules.ts), so both always agree on what counts as a trusted embed.
 * Dependency-free on purpose: the scanner's unit tests import it directly.
 */
export const ALLOWED_IFRAME_HOSTS: string[] = [
  'www.youtube.com',
  'youtube.com',
  'www.youtube-nocookie.com',
  'player.vimeo.com',
  'www.google.com',
  'maps.google.com',
  'docs.google.com',
  'open.spotify.com',
  'w.soundcloud.com',
  'www.linkedin.com',
  'embed.podcasts.apple.com',
  'www.facebook.com',
  'platform.twitter.com',
  'www.instagram.com',
  'player.simplecast.com',
  'www.buzzsprout.com',
  'anchor.fm',
  'podcasters.spotify.com',
  'canadiansme.ca',
  'www.canadiansme.ca',
]
