import { ask } from "./native.js";
import { MARK, hue, icon, siteIcon } from "./icons.js";

// The toolbar popup: logins for this site (or a search) on the left, and the
// selected one's details and editor on the right, like the app's. The popup is
// the extension's own page, which no website can reach, so it shows values and
// saves changes without asking, as the desktop app does. Fills and new
// two-factor codes run in the background worker, which outlives the popup.

const list = document.getElementById("logins");
const search = document.getElementById("search");
const clear = document.getElementById("clear");
const status = document.getElementById("status");
const site = document.getElementById("site");
const pane = document.getElementById("item-view");
let tab = null;
let logins = [];
let selected = 0;
let ticker = null;
// The login whose details the pane shows ("vault/id"), and items already read.
let shown = null;
const items = new Map();
let previewTimer = null;

function say(text, isError = false) {
  status.textContent = text;
  status.className = isError ? "error" : "";
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function button(label, cls, act) {
  const b = el("button", cls, label);
  b.addEventListener("click", act);
  return b;
}

// A button with an icon and an optional label.
function iconButton(name, label, cls, act, title = label) {
  const b = el("button", cls);
  b.innerHTML = icon(name);
  if (label) b.append(label);
  if (title) b.title = title;
  b.addEventListener("click", act);
  return b;
}

const onPage = () => tab && /^https?:/.test(tab.url || "");
const keyOf = (login) => `${login.vault}/${login.id}`;

function hostOf(login, item) {
  if (login?.host) return login.host;
  const href = item?.urls?.[0]?.href;
  if (!href) return "";
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:/i.test(href) ? href : `https://${href}`).host.replace(/^www\./, "");
  } catch {
    return "";
  }
}

// The site's icon, or the title's first letter on a colour of its own.
function avatar(title, host, large = false) {
  const box = el("div", `avatar${large ? " large" : ""}`, (title || "?").trim().charAt(0).toUpperCase() || "?");
  box.style.setProperty("--h", hue(title));
  siteIcon(host).then((src) => {
    if (!src) return;
    const img = el("img");
    img.src = src;
    img.alt = "";
    box.replaceChildren(img);
    box.classList.add("icon");
  });
  return box;
}

function setPane(...children) {
  clearInterval(ticker);
  pane.replaceChildren(...children);
  pane.scrollTop = 0;
}

function empty(text) {
  shown = null;
  const box = el("div", "empty");
  const mark = el("span", "brand");
  mark.innerHTML = MARK;
  box.append(mark, el("div", "", text));
  setPane(box);
}

// ---- The list ----

function render() {
  list.replaceChildren(
    ...logins.map((login, i) => {
      const li = el("li", i === selected ? "selected" : "");
      const text = el("div", "text");
      const title = el("div", "title");
      if (login.exact) title.insertAdjacentHTML("beforeend", icon("home"));
      title.append(el("span", "", login.title));
      if (login.exact) title.title = "Saved for this site";
      text.append(title, el("div", "sub", login.username || login.host || login.vaultName || ""));
      li.append(avatar(login.title, login.host), text);
      li.addEventListener("click", () => select(i));
      li.addEventListener("dblclick", () => choose(login));
      return li;
    }),
  );
  list.children[selected]?.scrollIntoView({ block: "nearest" });
}

function select(i) {
  selected = i;
  render();
  preview(logins[i]);
}

async function choose(login, force = false) {
  if (!login || !onPage()) return;
  say(force ? "Waiting for your approval in VisiPass…" : "Filling…");
  try {
    // The background worker fills: it outlives this popup, which closes when the
    // approval window takes focus.
    const reply = await chrome.runtime.sendMessage({ kind: "popup-fill", tabId: tab.id, login, force });
    if (!reply.ok) throw new Error(reply.error);
    if (reply.result.filled === 0) {
      say("No login fields found on this page.", true);
      return;
    }
    window.close();
  } catch (error) {
    say(error.message, true);
    if (/will not fill it here/.test(error.message)) {
      status.append(el("br"), button("Fill anyway (asks you to confirm)", "", () => choose(login, true)));
    }
  }
}

let timer = null;
search.addEventListener("input", () => {
  clear.hidden = !search.value;
  clearTimeout(timer);
  timer = setTimeout(load, 150);
});
search.addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown" && logins.length) { select(Math.min(selected + 1, logins.length - 1)); e.preventDefault(); }
  if (e.key === "ArrowUp" && logins.length) { select(Math.max(selected - 1, 0)); e.preventDefault(); }
  if (e.key === "Enter") { choose(logins[selected]); e.preventDefault(); }
  if (e.key === "Escape" && search.value) { resetSearch(); e.preventDefault(); }
});
function resetSearch() {
  search.value = "";
  clear.hidden = true;
  load();
  search.focus();
}
clear.addEventListener("click", resetSearch);
document.getElementById("open").addEventListener("click", (e) => {
  e.preventDefault();
  ask({ type: "open-app" }).then(() => window.close()).catch((error) => say(error.message, true));
});
document.getElementById("new").addEventListener("click", () => newLogin());

async function load() {
  const query = search.value.trim();
  if (!query && !onPage()) {
    logins = [];
    render();
    site.textContent = "Search";
    empty("Search your logins above, or + to add one.");
    return;
  }
  try {
    const result = query ? await ask({ type: "search", query }) : await ask({ type: "match", url: tab.url, unlock: true });
    logins = result.logins;
    // Keep the login the pane shows selected when the list reloads.
    selected = Math.max(0, logins.findIndex((l) => keyOf(l) === shown));
    site.textContent = query ? `Results for “${query}”` : `Logins for ${result.host || "this page"}`;
    say("");
    render();
    if (logins.length) preview(logins[selected]);
    else empty(query ? "Nothing matches. Try another search, or + to add a login." : `No saved logins for ${result.host || "this page"}. Search above, or + to add one.`);
  } catch (error) {
    say(error.message, true);
  }
}

// ---- One item ----

const isUser = (f) => f.purpose === "USERNAME";
const isPassword = (f) => f.purpose === "PASSWORD";
const isNotes = (f) => f.purpose === "NOTES";
const isOtp = (f) => f.type === "OTP";
const isCustom = (f) => !isUser(f) && !isPassword(f) && !isNotes(f) && !isOtp(f);
const concealed = (f) => f.type === "CONCEALED" || isPassword(f);
const value = (item, test) => item.fields?.find(test)?.value || "";

// Shows `login` in the pane: its header at once, the full item once the
// selection has settled, so arrowing through the list does not read every item.
function preview(login) {
  clearTimeout(previewTimer);
  if (!login) return;
  const key = keyOf(login);
  if (shown === key && pane.querySelector(".item-head")) return;
  shown = key;
  if (items.has(key)) return details(items.get(key), login);
  setPane(head(login.title, hostOf(login), [login.vaultName, "Login"]), actions(login, null));
  previewTimer = setTimeout(() => openItem(login), 180);
}

async function openItem(login) {
  const key = keyOf(login);
  try {
    const item = await ask({ type: "item", item: login.id, vault: login.vault });
    items.set(key, item);
    if (shown === key) details(item, login);
  } catch (error) {
    if (shown === key) setPane(head(login.title, hostOf(login), []), el("div", "note error", error.message));
  }
}

function head(title, host, meta, extra = null) {
  const box = el("div", "item-head");
  const text = el("div", "text");
  text.append(el("div", "item-title", title), el("div", "meta", meta.filter(Boolean).join(" · ")));
  box.append(avatar(title, host, true), text);
  if (extra) box.append(extra);
  return box;
}

function actions(login, item) {
  const tools = el("div", "tools");
  if (onPage()) tools.append(iconButton("key", "Fill", "pill primary", () => choose(login), "Fill this login on the page"));
  if (item) tools.append(iconButton("edit", "Edit", "pill", () => editor(item)));
  return tools;
}

function copy(text, target) {
  const was = target.innerHTML;
  const done = (ok) => {
    target.innerHTML = icon(ok ? "check" : "close");
    target.classList.add("done");
    setTimeout(() => {
      target.innerHTML = was;
      target.classList.remove("done");
    }, 1200);
  };
  navigator.clipboard.writeText(text).then(() => done(true), () => done(false));
}

// One line of a card: an icon, a label over its value, and Copy (and Show for
// a hidden value).
function row(iconName, label, text, { hidden = false, link = null } = {}) {
  const box = el("div", "field");
  box.insertAdjacentHTML("beforeend", icon(iconName));
  const body = el("div", "text");
  const dots = "•".repeat(12);
  const shownValue = el(link ? "a" : "div", hidden ? "value secret" : "value", hidden ? dots : text);
  if (link) shownValue.addEventListener("click", link);
  body.append(el("div", "label", label), shownValue);
  const tools = el("div", "actions");
  if (hidden) {
    let visible = false;
    const eye = iconButton("eye", "", "iconbtn", () => {
      visible = !visible;
      shownValue.textContent = visible ? text : dots;
      eye.innerHTML = icon(visible ? "eyeOff" : "eye");
      eye.title = visible ? "Hide" : "Show";
    }, "Show");
    tools.append(eye);
  }
  if (!link) tools.append(iconButton("copy", "", "iconbtn", (e) => copy(text, e.currentTarget), "Copy"));
  box.append(body, tools);
  return box;
}

function details(item, login) {
  login ||= { id: item.id, vault: item.vault.id, title: item.title };
  shown = keyOf(login);
  const star = iconButton(item.favorite ? "starFilled" : "star", "", `iconbtn${item.favorite ? " on" : ""}`, async () => {
    try {
      await ask({ type: "favorite", item: item.id, vault: item.vault.id, favorite: !item.favorite });
      item.favorite = !item.favorite;
      star.innerHTML = icon(item.favorite ? "starFilled" : "star");
      star.classList.toggle("on", item.favorite);
      star.title = item.favorite ? "Remove from favourites" : "Add to favourites";
    } catch (error) {
      say(error.message, true);
    }
  }, item.favorite ? "Remove from favourites" : "Add to favourites");
  const category = item.category ? item.category.charAt(0) + item.category.slice(1).toLowerCase().replace("_", " ") : "";
  const parts = [head(item.title, hostOf(login, item), [item.vault?.name, category], star), actions(login, item)];

  const main = el("div", "card");
  const user = value(item, isUser);
  if (user) main.append(row("user", "Username", user));
  const password = value(item, isPassword);
  if (password) main.append(row("key", "Password", password, { hidden: true }));
  const otp = item.fields?.find(isOtp);
  if (otp?.value) main.append(otpRow(otp.value));
  if (main.children.length) parts.push(main);

  const custom = (item.fields || []).filter((f) => isCustom(f) && f.value);
  if (custom.length) {
    const box = el("div", "card");
    for (const f of custom) {
      const label = [f.section?.label, f.label || f.id].filter(Boolean).join(" · ");
      box.append(row(concealed(f) ? "lock" : "field", label, f.value, { hidden: concealed(f) }));
    }
    parts.push(box);
  }

  if (item.urls?.length) {
    const box = el("div", "card");
    for (const u of item.urls) {
      box.append(
        row("globe", u.label || "Website", u.href, {
          link: () => {
            const href = /^[a-z][a-z0-9+.-]*:/i.test(u.href) ? u.href : `https://${u.href}`;
            if (/^https?:/i.test(href)) chrome.tabs.create({ url: href });
          },
        }),
      );
    }
    parts.push(box);
  }

  const notes = value(item, isNotes);
  if (notes) {
    const box = el("div", "card");
    const line = el("div", "field");
    line.insertAdjacentHTML("beforeend", icon("note"));
    const body = el("div", "text");
    body.append(el("div", "label", "Note"), el("div", "value notes", notes));
    line.append(body);
    box.append(line);
    parts.push(box);
  }

  if (!otp && onPage()) parts.push(button("+ Add a two-factor code from this page", "link", () => addTotp(login)));
  if (item.updated_at) parts.push(el("div", "note", `Changed ${new Date(item.updated_at).toLocaleString()}`));
  setPane(...parts);
  if (otp?.value) startTicker();
}

// ---- One-time codes, computed here (RFC 6238) ----

function base32(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let acc = 0;
  const out = [];
  for (const c of text.toUpperCase().replace(/[\s=-]/g, "")) {
    const i = alphabet.indexOf(c);
    if (i < 0) throw new Error("Not a valid setup key");
    acc = ((acc << 5) | i) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((acc >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  if (!out.length) throw new Error("Not a valid setup key");
  return new Uint8Array(out);
}

function totpParams(text) {
  text = text.trim();
  if (/^otpauth:/i.test(text)) {
    const url = new URL(text);
    if (url.host.toLowerCase() !== "totp") throw new Error("Only time-based (TOTP) codes are supported");
    const p = url.searchParams;
    return {
      key: base32(p.get("secret") || ""),
      digits: Number(p.get("digits") || 6),
      period: Number(p.get("period") || 30),
      hash: { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" }[(p.get("algorithm") || "SHA1").toUpperCase()] || "SHA-1",
    };
  }
  return { key: base32(text), digits: 6, period: 30, hash: "SHA-1" };
}

async function totpNow(text) {
  const p = totpParams(text);
  const key = await crypto.subtle.importKey("raw", p.key, { name: "HMAC", hash: p.hash }, false, ["sign"]);
  const now = Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / p.period);
  const message = new DataView(new ArrayBuffer(8));
  message.setUint32(0, Math.floor(counter / 2 ** 32));
  message.setUint32(4, counter >>> 0);
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, message.buffer));
  const o = h[h.length - 1] & 15;
  const n = (((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 10 ** p.digits;
  return { code: String(n).padStart(p.digits, "0"), left: p.period - (now % p.period) };
}

// The live code; `startTicker` updates it once the pane is showing.
let tick = null;
function otpRow(secret) {
  const box = el("div", "field");
  box.insertAdjacentHTML("beforeend", icon("clock"));
  const body = el("div", "text");
  const label = el("div", "label", "One-time code ");
  const left = el("span", "countdown", "");
  label.append(left);
  const code = el("div", "value code", "…");
  body.append(label, code);
  let digits = "";
  const tools = el("div", "actions");
  const copyButton = iconButton("copy", "", "iconbtn", (e) => {
    e.stopPropagation();
    if (digits) copy(digits, e.currentTarget);
  }, "Copy");
  tools.append(copyButton);
  box.append(body, tools);
  // Anywhere on the row copies the code, as authenticator apps do.
  box.classList.add("copyable");
  box.title = "Click to copy";
  box.addEventListener("click", () => digits && copy(digits, copyButton));
  tick = () =>
    totpNow(secret).then(
      (t) => {
        digits = t.code;
        // Shown in two halves, as authenticator apps do; copied without the space.
        const half = Math.ceil(t.code.length / 2);
        code.textContent = `${t.code.slice(0, half)} ${t.code.slice(half)}`;
        left.textContent = `${t.left}s`;
      },
      () => (code.textContent = "Not a valid code secret"),
    );
  return box;
}

function startTicker() {
  clearInterval(ticker);
  tick();
  ticker = setInterval(tick, 1000);
}

// ---- Editing, and new logins ----

function input(label, initial, { hidden = false, multiline = false } = {}) {
  const box = el("label", "edit");
  box.append(el("span", "label", label));
  const field = el(multiline ? "textarea" : "input");
  if (!multiline) field.type = hidden ? "password" : "text";
  field.value = initial || "";
  field.spellcheck = false;
  field.autocomplete = "off";
  box.append(field);
  return { box, field };
}

async function newLogin() {
  shown = null;
  setPane(el("div", "note", "Loading vaults…"));
  try {
    const { vaults } = await ask({ type: "vaults" });
    const { saveVault } = await chrome.storage.local.get("saveVault");
    const vault =
      vaults.find((v) => v.id === saveVault) || vaults.find((v) => /^(private|personal)$/i.test(v.name)) || vaults[0];
    if (!vault) throw new Error("VisiPass has no vault to save into");
    const origin = onPage() ? new URL(tab.url).origin : "";
    editor(
      {
        id: "",
        title: origin ? new URL(origin).host.replace(/^www\./, "") : "",
        category: "LOGIN",
        vault,
        tags: [],
        urls: origin ? [{ href: origin, primary: true }] : [],
        sections: [],
        fields: [],
      },
      vaults,
    );
  } catch (error) {
    setPane(el("div", "note error", error.message));
  }
}

// Back to whatever the list has selected.
function leaveEditor() {
  shown = null;
  if (logins[selected]) preview(logins[selected]);
  else empty("Search your logins above, or + to add one.");
}

function editor(item, vaults = null) {
  const isNew = !item.id;
  const header = el("div", "item-head");
  const text = el("div", "text");
  text.append(el("div", "item-title", isNew ? "New login" : `Edit ${item.title}`), el("div", "meta", item.vault?.name || ""));
  header.append(avatar(item.title, hostOf(null, item), true), text);
  const form = el("div", "form");
  const title = input("Title", item.title);
  form.append(title.box);
  let vaultSelect = null;
  if (isNew && vaults) {
    const box = el("label", "edit");
    vaultSelect = el("select");
    for (const v of vaults) {
      const option = el("option", "", v.name);
      option.value = v.id;
      option.selected = v.id === item.vault.id;
      vaultSelect.append(option);
    }
    box.append(el("span", "label", "Vault"), vaultSelect);
    form.append(box);
  }
  const username = input("Username", value(item, isUser));
  const password = input("Password", value(item, isPassword), { hidden: true });
  const passwordTools = el("div", "inline-tools");
  passwordTools.append(
    button("Generate", "small", async () => {
      try {
        password.field.value = (await ask({ type: "generate" })).password;
        password.field.type = "text";
      } catch (error) {
        say(error.message, true);
      }
    }),
    button("Show", "small", (e) => {
      password.field.type = password.field.type === "password" ? "text" : "password";
      e.target.textContent = password.field.type === "password" ? "Show" : "Hide";
    }),
  );
  password.box.append(passwordTools);
  form.append(username.box, password.box);

  // Websites: one input each, and a way to add another.
  const sites = el("div", "group");
  const siteInputs = [];
  const addSite = (href = "") => {
    const line = el("div", "line");
    const field = el("input");
    field.value = href;
    field.placeholder = "https://example.com";
    siteInputs.push(field);
    line.append(field, iconButton("close", "", "iconbtn", () => {
      siteInputs.splice(siteInputs.indexOf(field), 1);
      line.remove();
    }, "Remove"));
    sites.insertBefore(line, sites.lastChild);
  };
  sites.append(el("span", "label", "Websites"), button("+ Add website", "link", () => addSite()));
  for (const u of item.urls || []) addSite(u.href);
  form.append(sites);

  const otp = input("One-time code secret (otpauth:// link or setup key)", value(item, isOtp), { hidden: true });
  // Shown while you type in it, hidden again when you leave.
  otp.field.addEventListener("focus", () => (otp.field.type = "text"));
  otp.field.addEventListener("blur", () => (otp.field.type = "password"));
  // The code the secret makes, live, so a pasted secret shows at once that it works.
  const preview = el("div", "note");
  otp.box.append(preview);
  const showCode = () => {
    const text = otp.field.value.trim();
    if (!text) return (preview.textContent = "");
    totpNow(text).then(
      (t) => {
        const half = Math.ceil(t.code.length / 2);
        preview.textContent = `Code now: ${t.code.slice(0, half)} ${t.code.slice(half)} · ${t.left}s`;
        preview.className = "note";
      },
      (error) => {
        preview.textContent = error?.message || "Not a valid code secret";
        preview.className = "note error";
      },
    );
  };
  otp.field.addEventListener("input", showCode);
  form.append(otp.box);

  // Custom fields: label, value, and whether the value is hidden.
  const custom = el("div", "group");
  const rows = [];
  const addField = (field) => {
    const line = el("div", "line");
    const label = el("input");
    label.value = field.label || field.id || "";
    label.placeholder = "Label";
    const text = el("input");
    text.type = concealed(field) ? "password" : "text";
    text.value = field.value || "";
    text.placeholder = concealed(field) ? "Hidden value" : "Value";
    const entry = { field, label, text };
    rows.push(entry);
    line.append(label, text, iconButton("close", "", "iconbtn", () => {
      rows.splice(rows.indexOf(entry), 1);
      line.remove();
    }, "Remove"));
    custom.insertBefore(line, custom.lastChild);
  };
  const adders = el("div", "inline-tools");
  const fresh = (type) => ({ id: `custom${Date.now()}${rows.length}`, type, value: "" });
  adders.append(
    button("+ Text field", "link", () => addField(fresh("STRING"))),
    button("+ Hidden field", "link", () => addField(fresh("CONCEALED"))),
  );
  custom.append(el("span", "label", "Other fields"), adders);
  for (const f of (item.fields || []).filter(isCustom)) addField(f);
  form.append(custom);

  const notes = input("Note", value(item, isNotes), { multiline: true });
  form.append(notes.box);

  const note = el("div", "note");
  const save = async () => {
    try {
      if (!title.field.value.trim()) throw new Error("Give it a title");
      if (otp.field.value.trim()) totpParams(otp.field.value);
      const next = structuredClone(item);
      next.title = title.field.value.trim();
      if (vaultSelect) {
        next.vault = vaults.find((v) => v.id === vaultSelect.value);
        await chrome.storage.local.set({ saveVault: next.vault.id });
      }
      next.urls = siteInputs
        .map((f) => f.value.trim())
        .filter(Boolean)
        .map((href, i) => ({ href, primary: i === 0 }));
      const fields = next.fields || [];
      const builtin = (test, template, text) => {
        const at = fields.findIndex(test);
        if (at >= 0) fields[at].value = text;
        else if (text) fields.push({ ...template, value: text });
      };
      builtin(isUser, { id: "username", label: "username", type: "STRING", purpose: "USERNAME" }, username.field.value);
      builtin(isPassword, { id: "password", label: "password", type: "CONCEALED", purpose: "PASSWORD" }, password.field.value);
      builtin(isNotes, { id: "notesPlain", label: "notesPlain", type: "STRING", purpose: "NOTES" }, notes.field.value);
      const kept = fields.filter((f) => !isOtp(f) && !isCustom(f));
      const otpText = otp.field.value.trim();
      if (otpText) {
        const old = fields.find(isOtp);
        kept.push(old ? { ...old, value: otpText } : { id: `TOTP_${Date.now()}`, label: "one-time password", type: "OTP", value: otpText });
      }
      for (const r of rows) {
        if (!r.label.value.trim() && !r.text.value) continue;
        kept.push({ ...r.field, label: r.label.value.trim() || r.field.id, value: r.text.value });
      }
      next.fields = kept;
      note.textContent = "Saving…";
      note.className = "note";
      const saved = await ask({ type: "save-item", data: next });
      const login = { id: saved.id, vault: saved.vault.id, title: saved.title };
      items.set(keyOf(login), saved);
      details(saved, logins.find((l) => keyOf(l) === keyOf(login)) || login);
      load();
    } catch (error) {
      note.textContent = error.message;
      note.className = "note error";
    }
  };
  const tools = el("div", "tools");
  tools.append(button(isNew ? "Save" : "Save changes", "pill primary", save), button("Cancel", "pill", () => (isNew ? leaveEditor() : details(item))));
  if (!isNew) {
    const archive = button("Move to archive", "pill danger", () => {
      archive.replaceWith(
        el("span", "note", "Archive it?"),
        button("Yes, archive", "pill danger", async () => {
          try {
            await ask({ type: "archive", item: item.id, vault: item.vault.id });
            items.delete(`${item.vault.id}/${item.id}`);
            shown = null;
            await load();
            say(`Moved “${item.title}” to the archive. Restore it from the VisiPass app.`);
          } catch (error) {
            note.textContent = error.message;
            note.className = "note error";
          }
        }),
        button("No", "pill", () => editor(item, vaults)),
      );
    });
    tools.append(archive);
  }
  tools.style.marginTop = "14px";
  // Enter in any one-line field saves, as it would submit a form.
  form.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.tagName === "INPUT" && !e.isComposing) {
      e.preventDefault();
      save();
    }
  });
  setPane(header, form, tools, note);
  // setPane stops the detail view's ticker; this one keeps the preview's countdown live.
  showCode();
  ticker = setInterval(showCode, 1000);
  title.field.focus();
}

// Adds a two-factor code to `login` from the QR code on the page (a screenshot
// of the visible tab, read by VisiPass). VisiPass asks before saving it, which
// closes this popup, so the result shows on the page.
async function addTotp(login) {
  try {
    const image = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "jpeg", quality: 92 });
    say("Waiting for your approval in VisiPass…");
    const reply = await chrome.runtime.sendMessage({ kind: "popup-add-totp", tabId: tab.id, login, image });
    if (!reply.ok) throw new Error(reply.error);
    window.close();
  } catch (error) {
    say(error.message, true);
  }
}

async function start() {
  document.getElementById("brand").innerHTML = MARK;
  document.getElementById("search-icon").innerHTML = icon("search");
  document.getElementById("new").innerHTML = icon("plus");
  clear.innerHTML = icon("close");
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  ask({ type: "theme" })
    .then((theme) => {
      for (const [key, value] of Object.entries(theme)) {
        if (!value) continue;
        // The theme's font is a monospace one: it sets passwords and codes only.
        const name = { background: "bg", foreground: "fg", font: "mono" }[key] || key;
        document.documentElement.style.setProperty(`--${name}`, key === "font" ? `"${value}", ui-monospace, monospace` : value);
      }
    })
    .catch(() => {});
  if (!onPage()) {
    site.textContent = "Search";
    empty("Search your logins above, or + to add one.");
    search.focus();
    return;
  }
  say("Loading…");
  await load();
  search.focus();
}

start();
