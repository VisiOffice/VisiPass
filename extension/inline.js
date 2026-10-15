// The inline menu: a VisiPass mark in a login field and a "Log in as…" list of
// the logins saved for this site. It shows titles and usernames only; values are
// fetched by the background worker when you pick one, after VisiPass approves the
// site, and filled into this frame only.
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
    send({ kind: "theme" })
      .then((theme) => {
        for (const [key, value] of Object.entries(theme || {})) {
          if (!value) continue;
          const name = key === "background" ? "bg" : key === "foreground" ? "fg" : key;
          host.style.setProperty(`--${name}`, key === "font" ? `"${value}", monospace` : value);
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
    head.append(locked ? "VisiPass is locked" : "Log in as…");
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
    const rows = (logins || []).map((login, i) => {
      const row = el("div", `item${i === selected ? " selected" : ""}`);
      row.setAttribute("role", "option");
      row.append(el("div", "title", login.title), el("div", "sub", [login.username, login.host].filter(Boolean).join(" · ")));
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

  function openMenu() {
    if (!locked && (!logins || !logins.length)) return;
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
    const login = logins[i];
    if (!login) return;
    selected = i;
    renderMenu("Filling… approve in VisiPass if it asks.");
    try {
      const { filled } = await send({ kind: "page-fill", login });
      if (filled === 0) renderMenu("No login fields found here.", true);
      else {
        if (field) dismissed.add(field);
        closeMenu();
      }
    } catch (error) {
      renderMenu(error.message, true);
    }
  }

  async function show(target) {
    field = target;
    let result;
    try {
      result = await send({ kind: "page-logins" });
    } catch {
      return; // VisiPass not running: stay out of the way
    }
    if (field !== target) return;
    locked = Boolean(result.locked);
    logins = result.logins || [];
    if (!locked && !logins.length) return hide();
    ensureUi();
    selected = 0;
    updateMark();
    place();
    // Open on first focus, as other managers do; not again after Esc or a fill.
    // While locked only the mark shows: unlocking waits for a click.
    if (!locked && !dismissed.has(target)) openMenu();
  }

  document.addEventListener(
    "focusin",
    (e) => {
      const target = e.composedPath()[0];
      if (host && e.target === host) return;
      if (isLoginField(target) && shown(target)) show(target);
      else hide();
    },
    true,
  );

  document.addEventListener(
    "keydown",
    (e) => {
      if (!e.isTrusted || !field || e.composedPath()[0] !== field) return;
      if (!menuOpen) {
        if (e.key === "ArrowDown" && (locked || (logins && logins.length))) {
          openMenu();
          e.preventDefault();
        }
        return;
      }
      if (locked && e.key !== "Enter" && e.key !== "Escape") return;
      if (e.key === "ArrowDown") selected = Math.min(selected + 1, logins.length - 1);
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
})();
