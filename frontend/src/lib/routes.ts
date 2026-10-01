/**
 * Single source of truth for the simplified navigation.
 *
 * The app exposes six destinations; related screens are grouped into tabs. Any
 * older deep link is kept alive as a redirect so bookmarks and external links
 * (README, docs, demo scripts) never break.
 */
export const LEGACY_REDIRECTS: Record<string, string> = {
  '/predictions': '/detections',
  '/alerts': '/detections?tab=alerts',
  '/insights': '/model?tab=insights',
  '/datasets': '/data',
  '/simulation': '/data?tab=simulation',
}

export const NAV_DESTINATIONS = ['/dashboard', '/analyzer', '/detections', '/model', '/data', '/settings']
