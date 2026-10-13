import { ask, fill } from "./native.js";

// Fills run here, not in the popup: the popup closes as soon as the VisiPass
// approval window takes focus, and anything it was waiting on dies with it.

// Logins for a page, keyed by URL host, kept briefly so focusing field after
// field does not ask VisiPass each time. Titles and usernames only, never values.
const matches = new Map();
const MATCH_TTL = 30_000;

// `unlock` only when the human asked (a click, Ctrl+Shift+L): a page load never
// opens an unlock prompt, and gets `locked: true` while VisiPass is locked.
async function matchFor(url, unlock = false) {
  const host = new URL(url).host;
  const cached = matches.get(host);
  if (cached && Date.now() - cached.at < MATCH_TTL && !(unlock && cached.result.locked)) return cached.result;
  const result = await ask({ type: "match", url, unlock });
  if (result.locked) matches.delete(host);
  else matches.set(host, { at: Date.now(), result });
  return result;
}

let theme = null;

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  handle(message, sender).then(
    (result) => reply({ ok: true, result }),
    (error) => reply({ ok: false, error: error.message }),
  );
  return true;
});

async function handle(message, sender) {
  const fromPage = sender.tab && sender.id === chrome.runtime.id && sender.url && !sender.url.startsWith("chrome-extension:");
  switch (message.kind) {
    // From the inline menu. The page's own URL comes from Chrome (sender.url), never
    // from the message, and the fill goes only into the frame that asked.
    case "page-logins": {
      if (!fromPage) throw new Error("Not a page");
      const result = await matchFor(sender.url, Boolean(message.unlock));
      return { logins: result.logins, locked: Boolean(result.locked) };
    }
    case "page-fill": {
      if (!fromPage) throw new Error("Not a page");
      const target = { tabId: sender.tab.id, frameIds: [sender.frameId] };
      return { filled: await fill({ id: sender.tab.id, url: sender.url }, message.login, false, target) };
    }
    case "theme":
      theme ??= await ask({ type: "theme" }).catch(() => ({}));
      return theme;
    // From the popup: fill the active tab, every frame.
    case "popup-fill": {
      if (sender.tab) throw new Error("Not the popup");
      const tab = await chrome.tabs.get(message.tabId);
      return { filled: await fill(tab, message.login, message.force) };
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
