import { ask, fill } from "./native.js";

// Ctrl+Shift+L: fill the best login for this page (exact host first).
chrome.commands.onCommand.addListener(async (command, tab) => {
  if (command !== "fill-login" || !tab || !/^https?:/.test(tab.url || "")) return;
  try {
    const { logins } = await ask({ type: "match", url: tab.url });
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
