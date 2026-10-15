import { ask, fill } from "./native.js";

// Fills and saves run here, not in the popup: the popup closes as soon as the
// VisiPass approval window takes focus, and anything it was waiting on dies with it.

// Logins for a page, keyed by origin (scheme, host and port), kept briefly so focusing field after
// field does not ask VisiPass each time. Titles and usernames only, never values.
const matches = new Map();
const MATCH_TTL = 30_000;

// `unlock` only when the human asked (a click, Ctrl+Shift+L): a page load never
// opens an unlock prompt, and gets `locked: true` while VisiPass is locked.
async function matchFor(url, unlock = false) {
  const host = new URL(url).origin;
  const cached = matches.get(host);
  if (cached && Date.now() - cached.at < MATCH_TTL && !(unlock && cached.result.locked)) return cached.result;
  const result = await ask({ type: "match", url, unlock });
  if (result.locked) matches.delete(host);
  else matches.set(host, { at: Date.now(), result });
  return result;
}

let theme = null;

// ---- Saving logins ----
//
// A login submitted on a page waits here, per tab, for the human to answer the
// save card: in chrome.storage.session, which lives in memory only, survives
// this worker being stopped, and is closed to content scripts. Pages get the
// site, username and status to show, never the password back.
const OFFER_TTL = 5 * 60_000;
const offerKey = (tabId) => `offer:${tabId}`;

async function getOffer(tabId) {
  const key = offerKey(tabId);
  const offer = (await chrome.storage.session.get(key))[key];
  if (!offer) return null;
  if (Date.now() - offer.at > OFFER_TTL) {
    await chrome.storage.session.remove(key);
    return null;
  }
  return offer;
}

const setOffer = (tabId, offer) => chrome.storage.session.set({ [offerKey(tabId)]: { ...offer, at: Date.now() } });
const clearOffer = (tabId) => chrome.storage.session.remove(offerKey(tabId));
// The username from the first page of a two-page login, for the password page.
const userKey = (tabId) => `user:${tabId}`;
chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove([offerKey(tabId), userKey(tabId)]));

async function neverSave(origin) {
  const { never = [] } = await chrome.storage.local.get("never");
  return never.includes(origin);
}

// The vault new logins go to: the last one chosen on a save card, else a
// personal vault, else the first.
async function saveVault() {
  const { vaults } = await ask({ type: "vaults" });
  const { saveVault: chosen } = await chrome.storage.local.get("saveVault");
  const vault =
    vaults.find((v) => v.id === chosen) || vaults.find((v) => /^(private|personal)$/i.test(v.name)) || vaults[0];
  if (!vault) throw new Error("VisiPass has no vault to save into");
  return { vault, vaults };
}

// What the save card shows: never the password.
const cardOf = (offer) =>
  offer && {
    host: offer.host,
    username: offer.username,
    status: offer.status,
    title: offer.title,
    vaults: offer.vaults,
    vault: offer.vault,
    saved: offer.saved,
  };

function showCard(tabId, offer) {
  chrome.tabs.sendMessage(tabId, { kind: "show-card", card: cardOf(offer) }, { frameId: 0 }).catch(() => {});
}

// A form was submitted with a password. Decides whether to offer saving it.
async function submitted(tabId, url, username, password) {
  const origin = new URL(url).origin;
  if (!username) {
    const remembered = (await chrome.storage.session.get(userKey(tabId)))[userKey(tabId)];
    if (remembered && remembered.origin === origin && Date.now() - remembered.at < OFFER_TTL) username = remembered.username;
  }
  const offer = await getOffer(tabId);
  // The password VisiPass generated on this site: finish that login with the
  // username the form took. It was saved when it was generated.
  if (offer?.draft && offer.origin === origin && offer.draft.password === password) {
    const result = await ask({ type: "save", url, username, password, item: offer.draft.id, vault: offer.draft.vault });
    matches.delete(origin);
    await clearOffer(tabId);
    showCard(tabId, { host: offer.host, username, status: "saved", title: result.title, saved: result.vaultName });
    return;
  }
  if (await neverSave(origin)) return;
  const status = await ask({ type: "save", check: true, url, username, password });
  if (status.status === "same") return;
  const next = { url, origin, host: new URL(url).host.replace(/^www\./, ""), username, password, status: status.status };
  if (status.status === "changed") Object.assign(next, { id: status.id, vault: status.vault, title: status.title });
  else {
    const { vault, vaults } = await saveVault();
    Object.assign(next, { vault: vault.id, vaults });
  }
  await setOffer(tabId, next);
  showCard(tabId, next);
}

async function answer(tabId, choice, vault) {
  const offer = await getOffer(tabId);
  if (!offer || offer.draft) throw new Error("There is nothing to save");
  await clearOffer(tabId);
  if (choice === "never") {
    const { never = [] } = await chrome.storage.local.get("never");
    await chrome.storage.local.set({ never: [...new Set([...never, offer.origin])] });
    return {};
  }
  if (choice !== "save") return {};
  const message = { type: "save", url: offer.url, username: offer.username, password: offer.password };
  if (offer.status === "changed") Object.assign(message, { item: offer.id, vault: offer.vault });
  else {
    message.vault = vault || offer.vault;
    await chrome.storage.local.set({ saveVault: message.vault });
  }
  const result = await ask(message);
  matches.delete(offer.origin);
  return { title: result.title, vaultName: result.vaultName };
}

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  handle(message, sender).then(
    (result) => reply({ ok: true, result }),
    (error) => reply({ ok: false, error: error.message }),
  );
  return true;
});

async function handle(message, sender) {
  const fromPage = sender.tab && sender.id === chrome.runtime.id && sender.url && !sender.url.startsWith("chrome-extension:");
  const topFrame = fromPage && sender.frameId === 0;
  switch (message.kind) {
    // From the inline menu. The page's own URL comes from Chrome (sender.url), never
    // from the message, and the fill goes only into the document that asked: a
    // frame keeps its frameId when it navigates, its documentId does not.
    case "page-logins": {
      if (!fromPage) throw new Error("Not a page");
      const result = await matchFor(sender.url, Boolean(message.unlock));
      return { logins: result.logins, locked: Boolean(result.locked) };
    }
    case "page-fill": {
      if (!fromPage) throw new Error("Not a page");
      const target = sender.documentId
        ? { tabId: sender.tab.id, documentIds: [sender.documentId] }
        : { tabId: sender.tab.id, frameIds: [sender.frameId] };
      return await fill({ id: sender.tab.id, url: sender.url }, message.login, false, target);
    }
    // A password to suggest on a sign-up form. Nothing is saved until it is used.
    case "page-generate": {
      if (!fromPage) throw new Error("Not a page");
      return await ask({ type: "generate" });
    }
    // The suggested password was chosen: save it now, so a failed sign-up or a
    // closed tab never loses it, then let the page fill it.
    case "page-use-generated": {
      if (!fromPage || typeof message.password !== "string") throw new Error("Not a page");
      const { vault } = await saveVault();
      const result = await ask({
        type: "save",
        url: sender.url,
        username: String(message.username || ""),
        password: message.password,
        vault: vault.id,
      });
      const origin = new URL(sender.url).origin;
      matches.delete(origin);
      await setOffer(sender.tab.id, {
        origin,
        host: new URL(sender.url).host.replace(/^www\./, ""),
        draft: { id: result.id, vault: result.vault, password: message.password },
      });
      return { vaultName: result.vaultName };
    }
    case "page-username": {
      if (!fromPage || typeof message.username !== "string") throw new Error("Not a page");
      const origin = new URL(sender.url).origin;
      await chrome.storage.session.set({ [userKey(sender.tab.id)]: { origin, username: message.username, at: Date.now() } });
      return {};
    }
    case "page-submitted": {
      if (!fromPage || typeof message.password !== "string" || !message.password) throw new Error("Not a page");
      await submitted(sender.tab.id, sender.url, String(message.username || ""), message.password);
      return {};
    }
    // The save card, shown in the tab's top frame only.
    case "page-offer": {
      if (!topFrame) return null;
      const offer = await getOffer(sender.tab.id);
      return offer && !offer.draft ? cardOf(offer) : null;
    }
    case "page-offer-answer": {
      if (!topFrame) throw new Error("Not the page");
      return await answer(sender.tab.id, message.choice, message.vault);
    }
    case "theme":
      theme ??= await ask({ type: "theme" }).catch(() => ({}));
      return theme;
    // From the popup: fill the active tab, in every frame from the page's own origin.
    case "popup-fill": {
      if (sender.tab) throw new Error("Not the popup");
      const tab = await chrome.tabs.get(message.tabId);
      return await fill(tab, message.login, message.force);
    }
    // From the popup: a two-factor secret for a login, from a screenshot of the
    // page's QR code or a pasted setup key. The result shows on the page, since
    // the approval window closes the popup.
    case "popup-add-totp": {
      if (sender.tab) throw new Error("Not the popup");
      const tab = await chrome.tabs.get(message.tabId);
      const request = { type: "add-totp", url: tab.url, item: message.login.id, vault: message.login.vault };
      if (message.key) request.key = message.key;
      else request.image = message.image;
      try {
        const result = await ask(request);
        chrome.tabs
          .sendMessage(tab.id, { kind: "show-card", card: { status: "totp", title: result.title, code: result.code } }, { frameId: 0 })
          .catch(() => {});
        return result;
      } catch (error) {
        chrome.tabs
          .sendMessage(tab.id, { kind: "show-card", card: { status: "error", error: error.message } }, { frameId: 0 })
          .catch(() => {});
        throw error;
      }
    }
    default:
      throw new Error(`Unknown message "${message.kind}"`);
  }
}

// Ctrl+Shift+L: fill the best login for this page (exact host first).
chrome.commands.onCommand.addListener(async (command, tab) => {
  if (command !== "fill-login" || !tab || !/^https?:/.test(tab.url || "")) return;
  try {
    const { logins } = await matchFor(tab.url, true);
    if (!logins.length) {
      chrome.action.setBadgeText({ tabId: tab.id, text: "0" });
      return;
    }
    await fill(tab, logins[0]);
  } catch (error) {
    chrome.action.setBadgeText({ tabId: tab.id, text: "!" });
    chrome.action.setTitle({ tabId: tab.id, title: `VisiPass: ${error.message}` });
  }
});
