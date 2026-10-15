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

  function ensureUi() {
    if (host) return;
    host = document.createElement("visipass-inline");
    host.style.cssText =
      "all: initial !important; position: fixed !important; top: 0 !important; left: 0 !important; z-index: 2147483647 !important;";
    root = host.attachShadow({ mode: "closed" });
    root.innerHTML = `<style>
      :host { --bg:#1a1b26; --fg:#c0caf5; --accent:#7aa2f7; --muted:#9aa5ce; --danger:#f7768e; --font: ui-monospace, monospace; }
      * { box-sizing: border-box; }
      .mark { position: fixed; width: 22px; height: 22px; padding: 3px; border: 0; background: transparent; color: var(--accent); cursor: pointer; display: none; }
      .mark svg { width: 100%; height: 100%; display: block; }
      .mark .count { position: absolute; right: -4px; bottom: -4px; min-width: 14px; height: 14px; padding: 0 3px; border-radius: 7px;
        background: var(--accent); color: var(--bg); font: 600 9px/14px var(--font); text-align: center; }
      .menu { position: fixed; width: 280px; max-height: 300px; overflow-y: auto; display: none; background: var(--bg); color: var(--fg);
        border: 1px solid color-mix(in srgb, var(--fg) 18%, transparent); border-radius: 8px; box-shadow: 0 8px 28px rgba(0,0,0,.35);
        font: 12px/1.4 var(--font); padding: 4px 0; }
      .head { display: flex; align-items: center; gap: 6px; padding: 6px 12px; color: var(--muted); font-size: 11px; }
      .head svg { width: 12px; height: 12px; color: var(--accent); }
      .item { padding: 6px 12px; cursor: pointer; border-left: 2px solid transparent; }
      .item.selected, .item:hover { background: color-mix(in srgb, var(--fg) 8%, transparent); }
      .item.selected { border-left-color: var(--accent); }
      .title { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .sub { color: var(--muted); font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .status { padding: 6px 12px; color: var(--muted); font-size: 11px; }
      .status.error { color: var(--danger); }
      .sub.secret { color: var(--accent); font-size: 12px; letter-spacing: .02em; }
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
          const name = key === "background" ? "bg" : key === "foreground" ? "fg" : key;
          target.style.setProperty(`--${name}`, key === "font" ? `"${value}", monospace` : value);
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
    const menu = root.querySelector(".menu");
    const width = Math.max(Math.min(r.width, 340), 240);
    menu.style.width = `${width}px`;
    menu.style.left = `${Math.max(4, Math.min(r.right - width, innerWidth - width - 4))}px`;
    const below = r.bottom + 4;
    menu.style.top = below + 300 < innerHeight ? `${below}px` : `${Math.max(4, r.top - 4 - menu.offsetHeight)}px`;
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
      locked ? "VisiPass is locked" : mode === "new" ? "Password" : mode === "otp" ? "Fill the code from…" : "Log in as…",
    );
    if (locked) {
      const row = el("div", "item selected");
      row.setAttribute("role", "option");
      row.append(el("div", "title", "Unlock VisiPass"), el("div", "sub", "Then pick a login for this site"));
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
      if (entry.kind === "generate") {
        row.append(el("div", "title", "Use a strong password"), el("div", "sub secret", entry.password));
      } else {
        const login = entry.login;
        row.append(el("div", "title", login.title), el("div", "sub", [login.username, login.host].filter(Boolean).join(" · ")));
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
    if (mode === "new") return suggestion ? [{ kind: "generate", password: suggestion }] : [];
    return (logins || []).map((login) => ({ kind: "login", login }));
  }

  function openMenu() {
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
    if (!locked && !entries().length) return hide();
    ensureUi();
    selected = 0;
    updateMark();
    place();
    // Open on first focus, as other managers do; not again after Esc or a fill.
    // While locked only the mark shows: unlocking waits for a click.
    if (!locked && !dismissed.has(target) && !(mode === "new" && target.value)) openMenu();
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
      else if (e.key === "Escape") {
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
      :host { --bg:#1a1b26; --fg:#c0caf5; --accent:#7aa2f7; --muted:#9aa5ce; --danger:#f7768e; --font: ui-monospace, monospace; }
      * { box-sizing: border-box; }
      .card { width: 320px; background: var(--bg); color: var(--fg); font: 12px/1.45 var(--font); padding: 12px 14px;
        border: 1px solid color-mix(in srgb, var(--fg) 18%, transparent); border-radius: 8px; box-shadow: 0 8px 28px rgba(0,0,0,.35); }
      .head { display: flex; align-items: center; gap: 8px; font-weight: 600; margin-bottom: 6px; }
      .head svg { width: 14px; height: 14px; color: var(--accent); flex: none; }
      .line { color: var(--muted); word-break: break-all; }
      .code { font-size: 22px; letter-spacing: .15em; color: var(--accent); margin: 6px 0; }
      .error { color: var(--danger); }
      select { width: 100%; margin-top: 8px; background: transparent; color: var(--fg); font: inherit; padding: 4px;
        border: 1px solid color-mix(in srgb, var(--fg) 25%, transparent); }
      option { background: var(--bg); }
      .buttons { display: flex; gap: 6px; margin-top: 10px; flex-wrap: wrap; }
      button { font: inherit; padding: 4px 10px; cursor: pointer; background: transparent; color: var(--fg);
        border: 1px solid color-mix(in srgb, var(--fg) 25%, transparent); border-radius: 4px; }
      button.primary { background: var(--accent); color: var(--bg); border-color: var(--accent); }
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
    chrome.runtime.onMessage.addListener((message) => {
      if (message && message.kind === "show-card") renderCard(message.card);
    });
    // A login submitted on the previous page of this tab.
    send({ kind: "page-offer" })
      .then((offer) => offer && renderCard(offer))
      .catch(() => {});
  }
})();
