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
// real input events, so frameworks notice.
export function fillPage(username, password, totp) {
  const visible = (el) => el && el.getClientRects().length > 0 && !el.disabled && !el.readOnly;
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

// Asks VisiPass for one login's values and fills them into the tab's frames.
export async function fill(tab, login, force = false) {
  const values = await ask({ type: "fill", url: tab.url, item: login.id, vault: login.vault, force });
  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    func: fillPage,
    args: [values.username || "", values.password || "", values.totp || ""],
  });
  return results.reduce((n, r) => n + (r.result || 0), 0);
}
