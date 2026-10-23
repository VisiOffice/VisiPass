// Site icons and the small line icons the popup draws.
//
// Site icons come from Chrome's own favicon cache (the "favicon" permission):
// no network request, so nothing outside the browser learns which sites are in
// the vault. Chrome answers a site it has no icon for with a generic globe; that
// becomes null here, and the caller draws the title's first letter instead.

const cache = new Map();
let generic = null;

async function dataUrl(pageUrl) {
  const url = new URL(chrome.runtime.getURL("/_favicon/"));
  url.searchParams.set("pageUrl", pageUrl);
  url.searchParams.set("size", "64");
  const response = await fetch(url);
  const type = response.headers.get("content-type") || "image/png";
  const bytes = new Uint8Array(await response.arrayBuffer());
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return `data:${type};base64,${btoa(text)}`;
}

// A data: URL for `host`'s icon, or null.
export function siteIcon(host) {
  if (!host) return Promise.resolve(null);
  if (!cache.has(host)) {
    generic ??= dataUrl("https://visipass.invalid/").catch(() => null);
    cache.set(
      host,
      Promise.all([dataUrl(`https://${host}/`), generic])
        .then(([icon, none]) => (icon === none ? null : icon))
        .catch(() => null),
    );
  }
  return cache.get(host);
}

// Line icons (24×24, stroked with currentColor).
const path = {
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  close: '<path d="M6 6l12 12M18 6 6 18"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M17 6l3 3M14.5 8.5l2 2"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  note: '<path d="M5 3h10l4 4v14H5z"/><path d="M9 12h6M9 16h6M9 8h3"/>',
  field: '<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M7 10v4"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a10 10 0 0 0 5.4-1.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  check: '<path d="m5 12 5 5 9-10"/>',
  star: '<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1 6.2L12 17.3 6.5 20.2l1-6.2L3 9.6l6.2-.9z"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13 7 4 4"/>',
  back: '<path d="M15 5l-7 7 7 7"/>',
  home: '<path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
};

export function icon(name, cls = "") {
  const filled = name === "starFilled";
  const d = path[filled ? "star" : name];
  return `<svg class="ic ${cls}" viewBox="0 0 24 24" aria-hidden="true" fill="${filled ? "currentColor" : "none"}" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
}

// The VisiPass mark: a rounded square with a keyhole.
export const MARK =
  '<svg viewBox="0 0 512 512" aria-hidden="true"><path fill="currentColor" fill-rule="evenodd" d="M76,0 H436 A76,76 0 0 1 512,76 V436 A76,76 0 0 1 436,512 H76 A76,76 0 0 1 0,436 V76 A76,76 0 0 1 76,0 Z M228,400 H284 V287.2 A84,84 0 1 0 228,287.2 Z"/></svg>';

// A stable colour per title, for letter avatars.
export function hue(text) {
  let h = 0;
  for (const c of text || "?") h = (h * 31 + c.codePointAt(0)) % 360;
  return h;
}
