import { ask } from "./native.js";

// The toolbar popup: logins for this site (or a search), and for each one a
// details view and an editor, like the app's. The popup is the extension's own
// page, which no website can reach, so it shows values and saves changes
// without asking, as the desktop app does. Fills and new two-factor codes run
// in the background worker, which outlives the popup.

const list = document.getElementById("logins");
const search = document.getElementById("search");
const status = document.getElementById("status");
const site = document.getElementById("site");
const listView = document.getElementById("list-view");
const itemView = document.getElementById("item-view");
let tab = null;
let logins = [];
let selected = 0;
let ticker = null;

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

const onPage = () => tab && /^https?:/.test(tab.url || "");

// ---- The list ----

function render() {
  list.replaceChildren(
    ...logins.map((login, i) => {
      const li = el("li", i === selected ? "selected" : "");
      const title = el("div", "title", login.title);
      if (login.exact) title.append(el("span", "exact", "this site"));
      const sub = el("div", "sub", [login.username, login.host, login.vaultName].filter(Boolean).join(" · "));
      li.append(title, sub);
      li.addEventListener("click", () => openItem(login));
      return li;
    }),
  );
  list.children[selected]?.scrollIntoView({ block: "nearest" });
}

async function choose(login, force = false) {
  if (!login || !onPage()) return;
  say(force ? "Waiting for your approval in VisiPass…" : "Filling… approve in VisiPass if it asks.");
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
  clearTimeout(timer);
  timer = setTimeout(load, 150);
});
search.addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { selected = Math.min(selected + 1, logins.length - 1); render(); e.preventDefault(); }
  if (e.key === "ArrowUp") { selected = Math.max(selected - 1, 0); render(); e.preventDefault(); }
  if (e.key === "Enter") { choose(logins[selected]); e.preventDefault(); }
  if (e.key === "ArrowRight" && logins[selected]) { openItem(logins[selected]); e.preventDefault(); }
  if (e.key === "Escape" && search.value) { search.value = ""; load(); e.preventDefault(); }
});
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
    site.textContent = "Search your logins above, or + to add one.";
    return;
  }
  try {
    const result = query ? await ask({ type: "search", query }) : await ask({ type: "match", url: tab.url, unlock: true });
    logins = result.logins;
    selected = 0;
    site.textContent = query ? `Search results for “${query}”` : logins.length ? `Logins for ${result.host}` : `No saved logins for ${result.host || "this page"}. Search above, or + to add one.`;
    say("");
    render();
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

function show(view) {
  clearInterval(ticker);
  listView.hidden = view !== "list";
  itemView.hidden = view === "list";
  if (view === "list") search.focus();
}

async function openItem(login) {
  show("item");
  itemView.replaceChildren(el("div", "note", "Opening…"));
  try {
    details(await ask({ type: "item", item: login.id, vault: login.vault }), login);
  } catch (error) {
    itemView.replaceChildren(back(), el("div", "note error", error.message));
  }
}

function back(label = "‹ Back", act = () => show("list")) {
  return button(label, "back", act);
}

function copy(text, note) {
  navigator.clipboard.writeText(text).then(
    () => flash(note, "Copied"),
    () => flash(note, "Could not copy"),
  );
}

function flash(target, text) {
  const was = target.textContent;
  target.textContent = text;
  setTimeout(() => (target.textContent = was), 1200);
}

// A labelled value with Copy, and Show for a hidden one.
function row(label, text, hidden = false) {
  const box = el("div", "field");
  const name = el("div", "label", label);
  const shown = el("div", hidden ? "value mono" : "value", hidden ? "••••••••••" : text);
  const actions = el("div", "actions");
  if (hidden) {
    let visible = false;
    actions.append(
      button("Show", "small", (e) => {
        visible = !visible;
        shown.textContent = visible ? text : "••••••••••";
        e.target.textContent = visible ? "Hide" : "Show";
      }),
    );
  }
  actions.append(button("Copy", "small", (e) => copy(text, e.target)));
  box.append(name, shown, actions);
  return box;
}

function details(item, login) {
  login ||= { id: item.id, vault: item.vault.id, title: item.title };
  const header = el("div", "item-head");
  const star = button(item.favorite ? "★" : "☆", "icon star", async () => {
    try {
      await ask({ type: "favorite", item: item.id, vault: item.vault.id, favorite: !item.favorite });
      item.favorite = !item.favorite;
      star.textContent = item.favorite ? "★" : "☆";
    } catch (error) {
      say(error.message, true);
    }
  });
  header.append(back(), el("div", "item-title", item.title), star);
  const meta = el("div", "note", [item.vault?.name, item.category?.toLowerCase().replace("_", " ")].filter(Boolean).join(" · "));
  const tools = el("div", "tools");
  if (onPage()) tools.append(button("Fill", "primary", () => choose(login)));
  tools.append(button("Edit", "", () => editor(item)));
  const fields = el("div", "fields");
  const user = value(item, isUser);
  if (user) fields.append(row("username", user));
  const password = value(item, isPassword);
  if (password) fields.append(row("password", password, true));
  const otp = item.fields?.find(isOtp);
  if (otp?.value) fields.append(otpRow(otp.value));
  for (const f of (item.fields || []).filter(isCustom)) {
    if (!f.value) continue;
    const label = [f.section?.label, f.label || f.id].filter(Boolean).join(" · ");
    fields.append(row(label, f.value, concealed(f)));
  }
  for (const u of item.urls || []) {
    const box = el("div", "field");
    const link = el("a", "value", u.href);
    link.href = "#";
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const href = /^[a-z][a-z0-9+.-]*:/i.test(u.href) ? u.href : `https://${u.href}`;
      if (/^https?:/i.test(href)) chrome.tabs.create({ url: href });
    });
    box.append(el("div", "label", u.label || "website"), link, el("div", "actions"));
    fields.append(box);
  }
  const notes = value(item, isNotes);
  if (notes) {
    const box = el("div", "field");
    box.append(el("div", "label", "notes"), el("div", "value notes", notes), el("div", "actions"));
    fields.append(box);
  }
  if (!otp && onPage()) {
    fields.append(button("+ Add a two-factor code from this page", "link", () => addTotp(login)));
  }
  if (item.updated_at) fields.append(el("div", "note", `Changed ${new Date(item.updated_at).toLocaleString()}`));
  itemView.replaceChildren(header, meta, tools, fields);
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

function otpRow(secret) {
  const box = el("div", "field");
  const code = el("div", "value code", "…");
  const left = el("span", "left", "");
  const copyButton = button("Copy", "small", (e) => copy(code.textContent, e.target));
  const tick = () =>
    totpNow(secret).then(
      (t) => {
        code.textContent = t.code;
        left.textContent = `${t.left}s`;
      },
      () => (code.textContent = "Not a valid code secret"),
    );
  tick();
  ticker = setInterval(tick, 1000);
  const label = el("div", "label", "one-time code ");
  label.append(left);
  box.append(label, code, el("div", "actions"));
  box.lastChild.append(copyButton);
  return box;
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
  show("item");
  itemView.replaceChildren(el("div", "note", "Loading vaults…"));
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
    itemView.replaceChildren(back(), el("div", "note error", error.message));
  }
}

function editor(item, vaults = null) {
  clearInterval(ticker);
  const isNew = !item.id;
  const header = el("div", "item-head");
  header.append(
    back("Cancel", () => (isNew ? show("list") : details(item))),
    el("div", "item-title", isNew ? "New login" : "Edit"),
  );
  const form = el("div", "fields");
  const title = input("title", item.title);
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
    box.append(el("span", "label", "vault"), vaultSelect);
    form.append(box);
  }
  const username = input("username", value(item, isUser));
  const password = input("password", value(item, isPassword), { hidden: true });
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
    line.append(field, button("×", "small", () => {
      siteInputs.splice(siteInputs.indexOf(field), 1);
      line.remove();
    }));
    sites.insertBefore(line, sites.lastChild);
  };
  sites.append(el("span", "label", "websites"), button("+ Add website", "link", () => addSite()));
  for (const u of item.urls || []) addSite(u.href);
  form.append(sites);

  const otp = input("one-time code secret (otpauth:// link or setup key)", value(item, isOtp), { hidden: true });
  form.append(otp.box);

  // Custom fields: label, value, and whether the value is hidden.
  const custom = el("div", "group");
  const rows = [];
  const addField = (field) => {
    const line = el("div", "line");
    const label = el("input");
    label.value = field.label || field.id || "";
    label.placeholder = "label";
    const text = el("input");
    text.type = concealed(field) ? "password" : "text";
    text.value = field.value || "";
    text.placeholder = concealed(field) ? "hidden value" : "value";
    const entry = { field, label, text };
    rows.push(entry);
    line.append(label, text, button("×", "small", () => {
      rows.splice(rows.indexOf(entry), 1);
      line.remove();
    }));
    custom.insertBefore(line, custom.lastChild);
  };
  const adders = el("div", "inline-tools");
  const fresh = (type) => ({ id: `custom${Date.now()}${rows.length}`, type, value: "" });
  adders.append(
    button("+ Text field", "link", () => addField(fresh("STRING"))),
    button("+ Hidden field", "link", () => addField(fresh("CONCEALED"))),
  );
  custom.append(el("span", "label", "other fields"), adders);
  for (const f of (item.fields || []).filter(isCustom)) addField(f);
  form.append(custom);

  const notes = input("notes", value(item, isNotes), { multiline: true });
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
      matchesChanged();
      details(saved);
    } catch (error) {
      note.textContent = error.message;
      note.className = "note error";
    }
  };
  const tools = el("div", "tools");
  tools.append(button(isNew ? "Save" : "Save changes", "primary", save));
  if (!isNew) {
    const archive = button("Move to archive", "danger", () => {
      archive.replaceWith(
        el("span", "note", "Archive it? "),
        button("Yes, archive", "danger", async () => {
          try {
            await ask({ type: "archive", item: item.id, vault: item.vault.id });
            matchesChanged();
            show("list");
            await load();
            say(`Moved “${item.title}” to the archive. Restore it from the VisiPass app.`);
          } catch (error) {
            note.textContent = error.message;
            note.className = "note error";
          }
        }),
        button("No", "small", () => editor(item, vaults)),
      );
    });
    tools.append(archive);
  }
  itemView.replaceChildren(header, form, tools, note);
  title.field.focus();
}

// The list reflects a change the next time it loads.
function matchesChanged() {
  load();
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
    show("list");
    say(error.message, true);
  }
}

async function start() {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  ask({ type: "theme" })
    .then((theme) => {
      for (const [key, value] of Object.entries(theme)) {
        if (value) document.documentElement.style.setProperty(`--${key === "background" ? "bg" : key === "foreground" ? "fg" : key}`, key === "font" ? `"${value}", monospace` : value);
      }
    })
    .catch(() => {});
  if (!onPage()) {
    site.textContent = "Search your logins above.";
    search.focus();
    return;
  }
  say("Loading…");
  await load();
  search.focus();
}

start();
