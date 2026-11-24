// Settings and per-site pauses in chrome.storage.local.
// Holds origins and booleans only; never usernames, titles, passwords or codes.

export const FEATURES = ["menu", "save", "suggest", "passkeys"];

export const DEFAULT_SETTINGS = {
  menu: true,
  save: true,
  suggest: true,
  passkeys: true,
};

export const emptyPause = () => ({ menu: false, save: false, suggest: false, passkeys: false });

// Normalises a URL or bare host to an http(s) origin, or null if invalid.
export function normalizeOrigin(raw) {
  const text = String(raw || "").trim();
  if (!text) return null;
  // Prepend https:// unless the input already starts with a scheme (ignoring
  // host:port like "localhost:3000", where digits follow the colon).
  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(text) || /^[a-zA-Z][a-zA-Z0-9+.-]*:(?!\d+(\/|$))/.test(text);
  let url;
  try {
    // A bare host is https, except this computer's own, which is nearly always http.
    const local = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i.test(text);
    url = new URL(hasScheme ? text : `${local ? "http" : "https"}://${text}`);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (!url.hostname || url.username || url.password || !url.origin || url.origin === "null") return null;
  // A real host name or address: the parser lets spaces and the like through, percent-encoded.
  if (!/^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)$/i.test(url.hostname)) return null;
  return url.origin;
}

function cleanPause(entry) {
  return {
    menu: Boolean(entry?.menu),
    save: Boolean(entry?.save),
    suggest: Boolean(entry?.suggest),
    passkeys: Boolean(entry?.passkeys),
  };
}

// One-time migration from the old `quiet` and `never` arrays into `paused`.
// Once `paused` exists in storage, the old keys are never read again.
let migration = null;
export function ensureMigrated() {
  migration ??= (async () => {
    const { paused } = await chrome.storage.local.get("paused");
    if (paused !== undefined) return;
    const { quiet = [], never = [] } = await chrome.storage.local.get(["quiet", "never"]);
    const next = {};
    const mark = (raw, feature) => {
      const origin = normalizeOrigin(raw);
      if (!origin) return;
      next[origin] ??= emptyPause();
      next[origin][feature] = true;
    };
    if (Array.isArray(quiet)) for (const o of quiet) mark(o, "menu");
    if (Array.isArray(never)) for (const o of never) mark(o, "save");
    await chrome.storage.local.set({ paused: next });
    await chrome.storage.local.remove(["quiet", "never"]);
  })().catch((error) => {
    migration = null;
    throw error;
  });
  return migration;
}

export async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return {
    menu: settings?.menu ?? DEFAULT_SETTINGS.menu,
    save: settings?.save ?? DEFAULT_SETTINGS.save,
    suggest: settings?.suggest ?? DEFAULT_SETTINGS.suggest,
    passkeys: settings?.passkeys ?? DEFAULT_SETTINGS.passkeys,
  };
}

export async function setSettings(patch) {
  const current = await getSettings();
  const next = {
    menu: Boolean(patch.menu ?? current.menu),
    save: Boolean(patch.save ?? current.save),
    suggest: Boolean(patch.suggest ?? current.suggest),
    passkeys: Boolean(patch.passkeys ?? current.passkeys),
  };
  await chrome.storage.local.set({ settings: next });
  return next;
}

export async function getPaused() {
  await ensureMigrated();
  const { paused = {} } = await chrome.storage.local.get("paused");
  const clean = {};
  if (paused && typeof paused === "object") {
    for (const [raw, entry] of Object.entries(paused)) {
      const origin = normalizeOrigin(raw);
      if (origin) clean[origin] = cleanPause(entry);
    }
  }
  return clean;
}

export async function setPaused(paused) {
  await ensureMigrated();
  const clean = {};
  for (const [raw, entry] of Object.entries(paused || {})) {
    const origin = normalizeOrigin(raw);
    if (origin) clean[origin] = cleanPause(entry);
  }
  await chrome.storage.local.set({ paused: clean });
  return clean;
}

// Updates one feature flag for an origin; drops the row if all flags are off.
export async function setSitePause(rawOrigin, feature, value) {
  if (!FEATURES.includes(feature)) return;
  const origin = normalizeOrigin(rawOrigin);
  if (!origin) return;
  const paused = await getPaused();
  const entry = { ...(paused[origin] || emptyPause()), [feature]: Boolean(value) };
  if (FEATURES.some((f) => entry[f])) paused[origin] = entry;
  else delete paused[origin];
  await chrome.storage.local.set({ paused });
}

// Effective flags for one origin, combining global switches and per-site pauses.
export async function prefsFor(rawOrigin) {
  const origin = normalizeOrigin(rawOrigin);
  const [settings, paused] = await Promise.all([getSettings(), getPaused()]);
  const site = (origin && paused[origin]) || emptyPause();
  return {
    menu: settings.menu,
    quiet: site.menu,
    save: settings.save && !site.save,
    suggest: settings.menu && settings.suggest && !site.suggest,
    passkeys: settings.passkeys && !site.passkeys,
  };
}
