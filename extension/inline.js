// The inline menu: a VisiPass mark in a login field and a "Log in as…" list of
// the logins saved for this site. It shows titles and usernames only; values are
// fetched by the background worker when you pick one, after VisiPass approves the
// site, and filled into this frame only. On a new-password field it suggests a
// generated password instead; on a two-factor code field it fills the code.
//
// When a form with a password is submitted (by a real submit, Enter or click),
// the username and password go to the background worker, which asks VisiPass
// whether they are new or changed and has the top frame show a save card.
//
// Everything is drawn in a closed shadow root, so the page cannot read the list.
// Only real input picks a login: events the page dispatches itself
// (isTrusted false) are ignored, and nothing is picked unless Chrome reports the
// menu as actually visible (IntersectionObserver v2), so a page cannot hide it
// under a decoy and collect the click, or wait for an Enter nobody meant for it.
(() => {
  if (window.__visipassInline) return;
  window.__visipassInline = true;

  const MARK =
    '<svg viewBox="0 0 512 512" aria-hidden="true"><path fill="currentColor" fill-rule="evenodd" d="M76,0 H436 A76,76 0 0 1 512,76 V436 A76,76 0 0 1 436,512 H76 A76,76 0 0 1 0,436 V76 A76,76 0 0 1 76,0 Z M228,400 H284 V287.2 A84,84 0 1 0 228,287.2 Z"/></svg>';

  // Shared by the menu and the save card. The theme's font is monospace, so it
  // only sets passwords and codes; text uses the system's interface font.
  const BASE = `
      :host { --bg:#1a1b26; --fg:#c0caf5; --accent:#7aa2f7; --muted:#9aa5ce; --danger:#f7768e;
        --font: ui-sans-serif, system-ui, -apple-system, "Segoe UI", "Noto Sans", "Helvetica Neue", Arial, sans-serif;
        --mono: ui-monospace, monospace;
        --surface: color-mix(in srgb, var(--fg) 6%, var(--bg)); --surface-2: color-mix(in srgb, var(--fg) 11%, var(--bg));
        --line: color-mix(in srgb, var(--fg) 14%, transparent); }
      @media (prefers-color-scheme: light) {
        :host { --bg:#ffffff; --fg:#1f2328; --accent:#2f6fde; --muted:#5f6b7a; --danger:#c93c4a; }
      }
      * { box-sizing: border-box; }`;
  const KEY =
    '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M17 6l3 3M14.5 8.5l2 2"/></svg>';
  const DOTS =
    '<svg viewBox="0 0 24 24" aria-hidden="true" fill="currentColor"><circle cx="12" cy="5" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="12" cy="19" r="1.8"/></svg>';
  const EYE_OFF =
    '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a10 10 0 0 0 5.4-1.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>';
  const SEARCH =
    '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>';
  const LOCK =
    '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>';

  // A stable colour per title, for letter avatars (as in the popup).
  function hue(text) {
    let h = 0;
    for (const c of text || "?") h = (h * 31 + c.codePointAt(0)) % 360;
    return h;
  }

  // The site's icon (from the background worker, out of Chrome's favicon
  // cache), else the title's first letter; or one of the menu's own glyphs.
  function avatar(title, src, glyph) {
    const box = el("div", "avatar");
    box.style.setProperty("--h", hue(title));
    if (glyph) {
      box.innerHTML = glyph;
      box.classList.add("glyph");
    }
    else if (src && /^data:image\//.test(src)) {
      const img = el("img");
      img.src = src;
      img.alt = "";
      box.append(img);
      box.classList.add("icon");
    } else box.textContent = (title || "?").trim().charAt(0).toUpperCase() || "?";
    return box;
  }

  const send = (message) =>
    chrome.runtime.sendMessage(message).then((reply) => {
      if (!reply || !reply.ok) throw new Error((reply && reply.error) || "VisiPass did not answer");
      return reply.result;
    });

  const hintOf = (el) =>
    `${el.autocomplete} ${el.name} ${el.id} ${el.getAttribute("aria-label") || ""} ${el.placeholder}`;
  const scopeOf = (el) => el.form || el.closest("form, [role=dialog], main") || document.body;

  // A two-factor code field.
  function isOtpField(el) {
    if (!(el instanceof HTMLInputElement) || el.disabled || el.readOnly) return false;
    if (!["text", "tel", "number", ""].includes(el.type)) return false;
    if (el.autocomplete === "one-time-code") return true;
    return /(^|[^a-z])(otp|totp|2fa|mfa)([^a-z]|$)|one.?time|verification.?code|auth(entication)?.?code|security.?code|two.?factor/i.test(
      hintOf(el),
    );
  }

  // A password field for a new password: sign-up, or the new one on a change form.
  function isNewPassword(el) {
    if (!(el instanceof HTMLInputElement) || el.type !== "password" || el.disabled || el.readOnly) return false;
    if (/new-password/.test(el.autocomplete)) return true;
    if (/current-password/.test(el.autocomplete)) return false;
    if (/new|create|confirm|repeat|sign.?up|register/i.test(hintOf(el))) return true;
    const fields = [...scopeOf(el).querySelectorAll("input[type=password]")];
    // Two: password and confirmation. Three: current, new, confirmation.
    if (fields.length === 2 || (fields.length >= 3 && fields.indexOf(el) > 0)) return true;
    return /sign.?up|register|create.{0,16}account|join/i.test(`${document.title} ${location.pathname}`);
  }

  // The username that goes with a password field: the nearest textual field
  // before it that looks like one.
  function usernameFor(passwordField) {
    const inputs = [...scopeOf(passwordField).querySelectorAll("input")].filter(shown);
    const at = inputs.indexOf(passwordField);
    const before = (at < 0 ? inputs : inputs.slice(0, at)).reverse();
    const textual = (i) => ["text", "email", "tel", ""].includes(i.type) && i.value && !isOtpField(i);
    const field =
      before.find((i) => textual(i) && (i.type === "email" || /user|email|login|account/i.test(hintOf(i)))) ||
      before.find(textual);
    return field ? field.value.trim() : "";
  }

  // Sets a value the way typing does, so frameworks notice.
  function setValue(el, value) {
    const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value")?.set;
    if (setter) setter.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // A field we offer to fill: a password, or a username/email next to one.
  function isLoginField(el) {
    if (!(el instanceof HTMLInputElement) || el.disabled || el.readOnly) return false;
    if (el.type === "password") return true;
    if (!["text", "email", "tel", ""].includes(el.type)) return false;
    const hint = `${el.autocomplete} ${el.name} ${el.id} ${el.getAttribute("aria-label") || ""} ${el.placeholder}`;
    if (/search|query|coupon|promo|captcha|one-time-code|otp/i.test(hint)) return false;
    if (/username|email|e-mail/i.test(el.autocomplete)) return true;
    const scope = el.form || el.closest("form, [role=dialog], main, body");
    const hasPassword = scope && scope.querySelector("input[type=password]");
    return Boolean(hasPassword) || (/user|login|email|account|sign.?in/i.test(hint) && el.type !== "tel");
  }

  let host = null;
  let root = null;
  let field = null;
  let logins = null;
  let locked = false;
  let selected = 0;
  let menuOpen = false;
  let dismissed = new WeakSet();
  let menuVisible = false;
  // "login", "new" (suggest a password) or "otp" (fill a two-factor code).
  let mode = "login";
  let suggestion = null;
  // The ⋮ menu is showing instead of the logins.
  let options = false;
  // This site asked not to open the menu by itself; the mark still shows.
  let quiet = false;

  function ensureUi() {
    if (host) return;
    host = document.createElement("visipass-inline");
    host.style.cssText =
      "all: initial !important; position: fixed !important; top: 0 !important; left: 0 !important; z-index: 2147483647 !important;";
    root = host.attachShadow({ mode: "closed" });
    root.innerHTML = `<style>
      ${BASE}
      .mark { position: fixed; width: 22px; height: 22px; padding: 3px; border: 0; background: transparent; color: var(--accent); cursor: pointer; display: none; }
      .mark svg { width: 100%; height: 100%; display: block; }
      .mark .count { position: absolute; right: -5px; bottom: -5px; min-width: 15px; height: 15px; padding: 0 4px; border-radius: 8px;
        background: var(--accent); color: var(--bg); font: 700 9.5px/15px var(--font); text-align: center; box-shadow: 0 0 0 2px var(--bg); }
      .menu { position: fixed; width: 300px; max-height: 320px; overflow-y: auto; display: none; background: var(--bg); color: var(--fg);
        border: 1px solid var(--line); border-radius: 12px; box-shadow: 0 12px 32px rgba(0,0,0,.35), 0 2px 6px rgba(0,0,0,.2);
        font: 13px/1.4 var(--font); padding: 6px; scrollbar-width: thin; }
      .head { display: flex; align-items: center; gap: 7px; padding: 6px 8px 8px; color: var(--muted); font-size: 12px; font-weight: 600; }
      .head svg { width: 14px; height: 14px; color: var(--accent); }
      .item { display: flex; align-items: center; gap: 10px; padding: 7px 8px; cursor: pointer; border-radius: 9px; }
      .item:hover { background: var(--surface); }
      .item.selected { background: var(--surface-2); }
      .text { min-width: 0; flex: 1; }
      .title { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .sub { color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .status { padding: 6px 8px 4px; color: var(--muted); font-size: 12px; }
      .status.error { color: var(--danger); }
      .sub.secret { color: var(--accent); font: 13px/1.4 var(--mono); letter-spacing: .02em; }
      .avatar { --h: 200; width: 32px; height: 32px; border-radius: 8px; flex: none; display: grid; place-items: center; overflow: hidden;
        font-weight: 700; font-size: 14px; background: hsl(var(--h) 55% 50% / .18); color: color-mix(in srgb, hsl(var(--h) 60% 55%) 75%, var(--fg)); }
      .avatar.icon { background: #fff; }
      .avatar.glyph { background: var(--surface-2); color: var(--fg); }
      .avatar img { width: 20px; height: 20px; display: block; }
      .avatar svg { width: 17px; height: 17px; }
      .more { margin-left: auto; width: 24px; height: 24px; border: 0; border-radius: 7px; background: transparent; color: var(--muted);
        display: grid; place-items: center; cursor: pointer; padding: 0; }
      .more:hover, .more.on { background: var(--surface-2); color: var(--fg); }
      .more svg { width: 16px; height: 16px; color: currentColor; }
    </style>
    <button class="mark" title="VisiPass">${MARK}<span class="count"></span></button>
    <div class="menu" role="listbox"></div>`;
    root.querySelector(".mark").addEventListener("mousedown", (e) => {
      if (!e.isTrusted) return;
      e.preventDefault(); // keep focus in the field
      menuOpen ? closeMenu() : openMenu();
    });
    (document.documentElement || document.body).append(host);
    // Visible means unobscured, unfaded and untransformed for at least 100ms.
    new IntersectionObserver(
      (entries) => {
        menuVisible = entries[entries.length - 1].isVisible === true;
      },
      { trackVisibility: true, delay: 100 },
    ).observe(root.querySelector(".menu"));
    applyTheme(host);
  }

  function applyTheme(target) {
    send({ kind: "theme" })
      .then((theme) => {
        for (const [key, value] of Object.entries(theme || {})) {
          if (!value) continue;
          const name = { background: "bg", foreground: "fg", font: "mono" }[key] || key;
          target.style.setProperty(`--${name}`, key === "font" ? `"${value}", ui-monospace, monospace` : value);
        }
      })
      .catch(() => {});
  }

  function place() {
    if (!field || !host) return;
    const r = field.getBoundingClientRect();
    if (r.width === 0 || !field.isConnected) return hide();
    const mark = root.querySelector(".mark");
    mark.style.left = `${r.right - 28}px`;
    mark.style.top = `${r.top + (r.height - 22) / 2}px`;
    // Hang the menu off the field's right edge, under the mark, so the field
    // and the ones below it stay visible and clickable; slide it left only as
    // far as the window needs.
    const menu = root.querySelector(".menu");
    const width = 272;
    menu.style.width = `${width}px`;
    menu.style.left = `${Math.max(4, Math.min(r.right - 40, innerWidth - width - 4))}px`;
    const below = r.bottom + 4;
    menu.style.top = below + 320 < innerHeight ? `${below}px` : `${Math.max(4, r.top - 4 - menu.offsetHeight)}px`;
  }

  function hide() {
    closeMenu();
    if (root) root.querySelector(".mark").style.display = "none";
    field = null;
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function renderMenu(status, isError = false) {
    const menu = root.querySelector(".menu");
    const head = el("div", "head");
    head.innerHTML = MARK;
    head.append(
      locked ? "VisiPass is locked" : options ? "VisiPass" : mode === "new" ? "Password" : mode === "otp" ? "Fill the code from…" : "Log in as…",
    );
    if (!locked) {
      const more = el("button", `more${options ? " on" : ""}`);
      more.innerHTML = DOTS;
      more.title = options ? "Back" : "More";
      more.addEventListener("mousedown", (e) => {
        if (!e.isTrusted) return;
        e.preventDefault(); // keep focus in the field
        options = !options;
        selected = 0;
        renderMenu();
      });
      head.append(more);
    }
    if (locked) {
      const row = el("div", "item selected");
      row.setAttribute("role", "option");
      const text = el("div", "text");
      text.append(el("div", "title", "Unlock VisiPass"), el("div", "sub", "Then pick a login for this site"));
      row.append(avatar("VisiPass", null, LOCK), text);
      row.addEventListener("mousedown", (e) => {
        if (!e.isTrusted) return;
        e.preventDefault();
        unlock();
      });
      menu.replaceChildren(head, row);
      if (status) menu.append(el("div", `status${isError ? " error" : ""}`, status));
      return;
    }
    const rows = entries().map((entry, i) => {
      const row = el("div", `item${i === selected ? " selected" : ""}`);
      row.setAttribute("role", "option");
      const text = el("div", "text");
      if (entry.kind === "option") {
        text.append(el("div", "title", entry.title), el("div", "sub", entry.sub));
        row.append(avatar(entry.title, null, entry.glyph), text);
      } else if (entry.kind === "generate") {
        text.append(el("div", "title", "Use a strong password"), el("div", "sub secret", entry.password));
        row.append(avatar("password", null, KEY), text);
      } else {
        const login = entry.login;
        text.append(el("div", "title", login.title), el("div", "sub", login.username || login.host || ""));
        row.append(avatar(login.title, login.icon), text);
      }
      row.addEventListener("mousedown", (e) => {
        if (!e.isTrusted) return;
        e.preventDefault();
        choose(i);
      });
      return row;
    });
    menu.replaceChildren(head, ...rows);
    if (status) menu.append(el("div", `status${isError ? " error" : ""}`, status));
    menu.querySelector(".selected")?.scrollIntoView({ block: "nearest" });
  }

  // What the menu lists: the suggested password on a new-password field, else
  // the logins for this site.
  function entries() {
    if (options) return optionEntries();
    if (mode === "new") return suggestion ? [{ kind: "generate", password: suggestion }] : [];
    return (logins || []).map((login) => ({ kind: "login", login }));
  }

  // The ⋮ menu. Each acts only from a real click or key on the visible menu,
  // like picking a login.
  function optionEntries() {
    return [
      {
        kind: "option",
        glyph: EYE_OFF,
        title: quiet ? "Open on this site again" : "Don't open on this site",
        sub: quiet ? "Show this menu when a login field is focused" : "Click the VisiPass mark to open it",
        act: async () => {
          await send({ kind: "page-quiet", quiet: !quiet });
          quiet = !quiet;
          options = false;
          selected = 0;
          if (quiet) {
            if (field) dismissed.add(field);
            renderMenu("Won't open by itself on this site. Click the mark to open it.");
          } else renderMenu();
        },
      },
      {
        kind: "option",
        glyph: SEARCH,
        title: "Search all logins",
        sub: "Opens VisiPass in the toolbar",
        act: async () => {
          await send({ kind: "page-search" });
          closeMenu();
        },
      },
      {
        kind: "option",
        glyph: MARK,
        title: "Open VisiPass",
        sub: "The desktop app",
        act: async () => {
          await send({ kind: "page-open-app" });
          closeMenu();
        },
      },
    ];
  }

  function openMenu() {
    options = false;
    if (!locked && !entries().length) return;
    menuOpen = true;
    root.querySelector(".menu").style.display = "block";
    renderMenu();
    place();
  }

  function closeMenu() {
    menuOpen = false;
    if (root) root.querySelector(".menu").style.display = "none";
  }

  // A field a person can see: a page can hide one to collect a fill nobody sees.
  function shown(el) {
    if (!el || !el.isConnected) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 8 || r.height < 8) return false;
    for (let n = el; n; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (s.display === "none" || s.visibility !== "visible" || Number(s.opacity) < 0.5) return false;
    }
    return true;
  }

  async function unlock() {
    renderMenu("Unlock in the VisiPass window…");
    try {
      const result = await send({ kind: "page-logins", unlock: true });
      locked = Boolean(result.locked);
      logins = result.logins || [];
      selected = 0;
      if (!logins.length) return renderMenu("No saved logins for this site.");
      updateMark();
      renderMenu();
    } catch (error) {
      renderMenu(error.message, true);
    }
  }

  function updateMark() {
    const mark = root.querySelector(".mark");
    mark.style.display = "block";
    mark.title = locked ? "VisiPass is locked: click to unlock" : "VisiPass";
    mark.style.opacity = locked ? "0.55" : "1";
    const count = mark.querySelector(".count");
    count.textContent = !locked && logins.length > 1 ? String(logins.length) : "";
    count.style.display = !locked && logins.length > 1 ? "block" : "none";
  }

  async function choose(i) {
    if (!menuVisible || !shown(field)) {
      return renderMenu("VisiPass can't see this menu clearly on the page, so it won't fill here.", true);
    }
    if (locked) return unlock();
    const entry = entries()[i];
    if (!entry) return;
    selected = i;
    if (entry.kind === "option") {
      try {
        await entry.act();
      } catch (error) {
        renderMenu(error.message, true);
      }
      return;
    }
    if (entry.kind === "generate") return useSuggestion(entry.password);
    const login = entry.login;
    renderMenu("Filling… approve in VisiPass if it asks.");
    try {
      const { filled, totp } = await send({ kind: "page-fill", login });
      if (mode === "otp" && !totp) {
        renderMenu("This login has no two-factor code saved. Add one from the VisiPass button in the toolbar.", true);
      } else if (filled === 0) renderMenu("No login fields found here.", true);
      else {
        if (field) dismissed.add(field);
        closeMenu();
      }
    } catch (error) {
      renderMenu(error.message, true);
    }
  }

  // Saves the suggested password first, so a failed sign-up or a closed tab
  // never loses it, then fills it into this field and the confirmation after it.
  async function useSuggestion(password) {
    renderMenu("Saving the new password in VisiPass…");
    try {
      const { vaultName } = await send({ kind: "page-use-generated", password, username: usernameFor(field) });
      const fields = [...scopeOf(field).querySelectorAll("input[type=password]")].filter(shown);
      for (const f of fields.slice(Math.max(0, fields.indexOf(field)))) setValue(f, password);
      dismissed.add(field);
      suggestion = null;
      closeMenu();
      renderCard({ status: "saved", title: location.host.replace(/^www\./, ""), saved: vaultName, generated: true });
    } catch (error) {
      renderMenu(error.message, true);
    }
  }

  async function show(target) {
    field = target;
    mode = isOtpField(target) ? "otp" : isNewPassword(target) ? "new" : "login";
    let result;
    try {
      result =
        mode === "new"
          ? { logins: [], locked: false, ...(await send({ kind: "page-generate" })) }
          : await send({ kind: "page-logins" });
    } catch (error) {
      // VisiPass not running: stay out of the way, but say why in the console.
      console.debug("VisiPass:", error.message);
      return;
    }
    if (field !== target) return;
    locked = Boolean(result.locked);
    logins = result.logins || [];
    suggestion = mode === "new" ? result.password : null;
    if (mode !== "new") quiet = Boolean(result.quiet);
    if (!locked && !entries().length) return hide();
    ensureUi();
    selected = 0;
    updateMark();
    place();
    // Open on first focus, as other managers do; not again after Esc or a fill.
    // While locked only the mark shows: unlocking waits for a click.
    if (!locked && !quiet && !dismissed.has(target) && !(mode === "new" && target.value)) openMenu();
  }

  document.addEventListener(
    "focusin",
    (e) => {
      const target = e.composedPath()[0];
      if (host && e.target === host) return;
      if ((isLoginField(target) || isOtpField(target)) && shown(target)) show(target);
      else hide();
    },
    true,
  );

  document.addEventListener(
    "keydown",
    (e) => {
      if (!e.isTrusted || !field || e.composedPath()[0] !== field) return;
      if (!menuOpen) {
        if (e.key === "ArrowDown" && (locked || entries().length)) {
          openMenu();
          e.preventDefault();
        }
        return;
      }
      if (locked && e.key !== "Enter" && e.key !== "Escape") return;
      if (e.key === "ArrowDown") selected = Math.min(selected + 1, entries().length - 1);
      else if (e.key === "ArrowUp") selected = Math.max(selected - 1, 0);
      else if (e.key === "Enter") choose(selected);
      else if (e.key === "Escape" && options) {
        options = false;
        selected = 0;
      } else if (e.key === "Escape") {
        dismissed.add(field);
        closeMenu();
      } else return;
      e.preventDefault();
      e.stopPropagation();
      if (menuOpen && e.key !== "Enter") renderMenu();
    },
    true,
  );

  document.addEventListener("mousedown", (e) => {
    if (host && e.composedPath().includes(host)) return;
    if (field && e.composedPath()[0] !== field) closeMenu();
  }, true);
  addEventListener("scroll", place, true);
  addEventListener("resize", place);

  // ---- Saving what was typed ----

  // A form with a password was submitted. Only real input counts: a page
  // cannot submit for you to get a card shown.
  let lastSent = "";
  function capture(scope) {
    if (!scope) return;
    const passwords = [...scope.querySelectorAll("input[type=password]")].filter((f) => f.value && shown(f));
    if (!passwords.length) {
      // The username step of a two-page login: remember it for the password page.
      const user = [...scope.querySelectorAll("input")].find(
        (i) => shown(i) && i.value && (i.type === "email" || /username|email/i.test(i.autocomplete)),
      );
      if (user) send({ kind: "page-username", username: user.value.trim() }).catch(() => {});
      return;
    }
    // A new password if the form says which; else the last one (new and
    // confirmation follow the current one); else the only one.
    const fresh = passwords.find((f) => /new-password/.test(f.autocomplete));
    const password = (fresh || passwords[passwords.length - 1]).value;
    const username = usernameFor(passwords[0]);
    const key = `${username}\n${password}`;
    if (key === lastSent) return;
    lastSent = key;
    setTimeout(() => {
      if (lastSent === key) lastSent = "";
    }, 5000);
    send({ kind: "page-submitted", username, password }).catch(() => {});
  }

  document.addEventListener("submit", (e) => e.isTrusted && capture(e.target), true);
  document.addEventListener(
    "keydown",
    (e) => {
      if (!e.isTrusted || e.key !== "Enter" || menuOpen) return;
      const target = e.composedPath()[0];
      if (target instanceof HTMLInputElement && (target.type === "password" || isLoginField(target))) {
        capture(scopeOf(target));
      }
    },
    true,
  );
  document.addEventListener(
    "click",
    (e) => {
      const path = e.composedPath();
      if (!e.isTrusted || (host && path.includes(host)) || (card && path.includes(card))) return;
      const button = path.find((n) => n instanceof Element && n.matches("button, input[type=submit], input[type=button], [role=button]"));
      if (!button) return;
      const scope = scopeOf(button);
      if (scope.querySelector("input[type=password], input[type=email]")) capture(scope);
    },
    true,
  );

  // ---- The save card ----
  //
  // "Save login?", "Update password?", "Saved", or a new two-factor code, at the
  // top right of the page in its own closed shadow root. Its buttons act only on
  // real clicks while Chrome reports the card as visible.
  let card = null;
  let cardRoot = null;
  let cardVisible = false;
  let cardTimer = null;

  function ensureCard() {
    if (card) return;
    card = document.createElement("visipass-card");
    card.style.cssText =
      "all: initial !important; position: fixed !important; top: 16px !important; right: 16px !important; z-index: 2147483647 !important;";
    cardRoot = card.attachShadow({ mode: "closed" });
    cardRoot.innerHTML = `<style>
      ${BASE}
      .card { width: 340px; background: var(--bg); color: var(--fg); font: 13px/1.45 var(--font); padding: 14px 16px 16px;
        border: 1px solid var(--line); border-radius: 14px; box-shadow: 0 12px 32px rgba(0,0,0,.35), 0 2px 6px rgba(0,0,0,.2); }
      .head { display: flex; align-items: center; gap: 10px; font-weight: 650; font-size: 14px; margin-bottom: 8px; }
      .head svg { width: 26px; height: 26px; color: var(--accent); flex: none; }
      .line { color: var(--muted); word-break: break-all; }
      .code { font: 26px/1.3 var(--mono); letter-spacing: .15em; color: var(--accent); margin: 8px 0; }
      .error { color: var(--danger); }
      select { width: 100%; height: 34px; margin-top: 10px; background: var(--surface); color: var(--fg); font: inherit; padding: 0 8px;
        border: 1px solid var(--line); border-radius: 8px; outline: none; }
      select:focus { border-color: var(--accent); }
      option { background: var(--bg); }
      .buttons { display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap; }
      button { font: 600 13px/1 var(--font); height: 32px; padding: 0 14px; cursor: pointer; background: var(--surface); color: var(--fg);
        border: 1px solid var(--line); border-radius: 999px; }
      button:hover { background: var(--surface-2); }
      button.primary { background: var(--accent); color: var(--bg); border-color: transparent; }
      button.primary:hover { filter: brightness(1.08); }
    </style><div class="card"></div>`;
    (document.documentElement || document.body).append(card);
    new IntersectionObserver(
      (entries) => {
        cardVisible = entries[entries.length - 1].isVisible === true;
      },
      { trackVisibility: true, delay: 100 },
    ).observe(cardRoot.querySelector(".card"));
    applyTheme(card);
  }

  function closeCard() {
    clearTimeout(cardTimer);
    card?.remove();
    card = cardRoot = null;
    cardVisible = false;
  }

  function button(label, primary, act) {
    const b = el("button", primary ? "primary" : "", label);
    b.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      if (!cardVisible) return;
      act();
    });
    return b;
  }

  function renderCard(c) {
    if (!c) return;
    ensureCard();
    clearTimeout(cardTimer);
    const box = cardRoot.querySelector(".card");
    const head = el("div", "head");
    head.innerHTML = MARK;
    const lines = [];
    const buttons = el("div", "buttons");
    const answer = async (choice, vault) => {
      box.replaceChildren(head, el("div", "line", choice === "save" ? "Saving… approve in VisiPass if it asks." : ""));
      try {
        const result = await send({ kind: "page-offer-answer", choice, vault });
        if (choice === "save") renderCard({ status: "saved", title: result.title, saved: result.vaultName });
        else closeCard();
      } catch (error) {
        renderCard({ status: "error", error: error.message });
      }
    };
    if (c.status === "new") {
      head.append(`Save login for ${c.host}?`);
      lines.push(el("div", "line", c.username || "No username"));
      const select = el("select");
      for (const v of c.vaults || []) {
        const option = el("option", "", v.name);
        option.value = v.id;
        option.selected = v.id === c.vault;
        select.append(option);
      }
      lines.push(select);
      buttons.append(
        button("Save", true, () => answer("save", select.value)),
        button("Not now", false, () => answer("dismiss")),
        button("Never for this site", false, () => answer("never")),
      );
    } else if (c.status === "changed") {
      head.append(`Update the password for ${c.title}?`);
      lines.push(el("div", "line", c.username || "No username"));
      buttons.append(button("Update", true, () => answer("save")), button("Not now", false, () => answer("dismiss")));
    } else if (c.status === "saved") {
      head.append(c.generated ? "New password saved in VisiPass" : "Saved in VisiPass");
      lines.push(el("div", "line", [c.title, c.saved].filter(Boolean).join(" · ")));
      if (c.generated) lines.push(el("div", "line", "Finish signing up; VisiPass adds the username when you submit."));
      cardTimer = setTimeout(closeCard, 6000);
    } else if (c.status === "totp") {
      head.append(`Two-factor code added to ${c.title}`);
      lines.push(el("div", "code", c.code || ""), el("div", "line", "Enter this code on the page to finish turning on two-factor."));
      buttons.append(button("Done", false, closeCard));
      cardTimer = setTimeout(closeCard, 60_000);
    } else {
      head.append("VisiPass");
      lines.push(el("div", "line error", c.error || "Something went wrong"));
      buttons.append(button("Close", false, closeCard));
    }
    box.replaceChildren(head, ...lines, ...(buttons.children.length ? [buttons] : []));
  }

  if (window === window.top) {
    // Lets the toolbar icon follow the browser's light or dark mode.
    const dark = matchMedia("(prefers-color-scheme: dark)");
    const report = () => send({ kind: "page-scheme", scheme: dark.matches ? "dark" : "light" }).catch(() => {});
    report();
    dark.addEventListener("change", report);
    chrome.runtime.onMessage.addListener((message) => {
      if (message && message.kind === "show-card") renderCard(message.card);
    });
    // A login submitted on the previous page of this tab.
    send({ kind: "page-offer" })
      .then((offer) => offer && renderCard(offer))
      .catch(() => {});
  }
})();
