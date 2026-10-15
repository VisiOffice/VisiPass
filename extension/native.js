// Talks to VisiPass through the native-messaging host (`vp`), which relays to visipassd.
export const HOST = "com.visioffice.visipass";

let counter = 0;

export function ask(message) {
  return new Promise((resolve, reject) => {
    // The message's own fields never override its id.
    chrome.runtime.sendNativeMessage(HOST, { ...message, id: ++counter }, (reply) => {
      if (chrome.runtime.lastError) {
        reject(new Error("VisiPass is not connected. Run `vp browser install`, then reload this extension."));
      } else if (!reply || !reply.ok) {
        reject(new Error((reply && reply.error) || "VisiPass did not answer"));
      } else {
        resolve(reply.result);
      }
    });
  });
}

// Runs inside the page, injected only when you ask to fill. Fills the visible
// username and password fields (or a one-time-code field on a 2FA step) with
// real input events, so frameworks notice. Does nothing in a frame from another
// origin than the one VisiPass approved: an ad iframe, or a frame that navigated
// away while the approval was open.
export function fillPage(origin, username, password, totp) {
  if (location.origin !== origin) return 0;
  // Visible to a person: a page can hide a password field (opacity, 1px, off
  // screen, visibility) to collect a fill nobody sees.
  const visible = (el) => {
    if (!el || el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 8 || r.height < 8 || r.right <= 0 || r.left >= innerWidth || r.top + scrollY < 0) return false;
    for (let n = el; n; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (s.display === "none" || s.visibility !== "visible" || Number(s.opacity) < 0.5) return false;
    }
    return true;
  };
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value")?.set;
    if (setter) setter.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const inputs = [...document.querySelectorAll("input")].filter(visible);
  const password_field = inputs.find((i) => i.type === "password");
  const textual = (i) => ["text", "email", "tel", ""].includes(i.type);
  let user_field = null;
  if (password_field) {
    const before = inputs.slice(0, inputs.indexOf(password_field)).reverse();
    user_field = before.find((i) => textual(i) && /user|email|login|name|account/i.test(i.name + i.id + i.autocomplete)) || before.find(textual);
  } else {
    user_field = inputs.find((i) => i.type === "email" || /user|email|login/i.test(i.name + i.id + i.autocomplete));
  }
  const otp_field = inputs.find((i) => i.autocomplete === "one-time-code" || /otp|totp|2fa|mfa|one.?time/i.test(i.name + i.id));
  let filled = 0;
  if (password_field && password) { set(password_field, password); filled++; }
  if (user_field && username && user_field !== otp_field) { set(user_field, username); filled++; }
  if (!password_field && otp_field && totp) { set(otp_field, totp); filled++; }
  (password_field || user_field || otp_field)?.focus();
  return filled;
}

// Asks VisiPass for one login's values and fills them into the tab's frames
// from the page's own origin (or only `target`'s document). `tab.url` is the
// page VisiPass checks the login against.
export async function fill(tab, login, force = false, target = { tabId: tab.id, allFrames: true }) {
  const origin = new URL(tab.url).origin;
  const values = await ask({ type: "fill", url: tab.url, item: login.id, vault: login.vault, force });
  const results = await chrome.scripting.executeScript({
    target,
    func: fillPage,
    args: [origin, values.username || "", values.password || "", values.totp || ""],
  });
  return results.reduce((n, r) => n + (r.result || 0), 0);
}
