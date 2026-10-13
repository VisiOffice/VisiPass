import { ask } from "./native.js";

const list = document.getElementById("logins");
const search = document.getElementById("search");
const status = document.getElementById("status");
const site = document.getElementById("site");
let tab = null;
let logins = [];
let selected = 0;

function say(text, isError = false) {
  status.textContent = text;
  status.className = isError ? "error" : "";
}

function render() {
  list.replaceChildren(
    ...logins.map((login, i) => {
      const li = document.createElement("li");
      li.className = i === selected ? "selected" : "";
      const title = document.createElement("div");
      title.className = "title";
      title.textContent = login.title;
      if (login.exact) {
        const tag = document.createElement("span");
        tag.className = "exact";
        tag.textContent = "this site";
        title.append(tag);
      }
      const sub = document.createElement("div");
      sub.className = "sub";
      sub.textContent = [login.username, login.host, login.vaultName].filter(Boolean).join(" · ");
      li.append(title, sub);
      li.addEventListener("click", () => choose(i));
      return li;
    }),
  );
  list.children[selected]?.scrollIntoView({ block: "nearest" });
}

async function choose(i, force = false) {
  const login = logins[i];
  if (!login || !tab) return;
  say(force ? "Waiting for your approval in VisiPass…" : "Filling… approve in VisiPass if it asks.");
  try {
    // The background worker fills: it outlives this popup, which closes when the
    // approval window takes focus.
    const reply = await chrome.runtime.sendMessage({ kind: "popup-fill", tabId: tab.id, login, force });
    if (!reply.ok) throw new Error(reply.error);
    const { filled } = reply.result;
    if (filled === 0) {
      say("No login fields found on this page.", true);
      return;
    }
    window.close();
  } catch (error) {
    say(error.message, true);
    if (/will not fill it here/.test(error.message)) {
      const anyway = document.createElement("button");
      anyway.textContent = "Fill anyway (asks you to confirm)";
      anyway.addEventListener("click", () => choose(i, true));
      status.append(document.createElement("br"), anyway);
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
  if (e.key === "Enter") { choose(selected); e.preventDefault(); }
  if (e.key === "Escape" && search.value) { search.value = ""; load(); e.preventDefault(); }
});
document.getElementById("open").addEventListener("click", (e) => {
  e.preventDefault();
  ask({ type: "open-app" }).then(() => window.close()).catch((error) => say(error.message, true));
});

async function load() {
  const query = search.value.trim();
  try {
    const result = query ? await ask({ type: "search", query }) : await ask({ type: "match", url: tab.url });
    logins = result.logins;
    selected = 0;
    site.textContent = query ? `Search results for “${query}”` : logins.length ? `Logins for ${result.host}` : `No saved logins for ${result.host || "this page"}. Search above.`;
    say("");
    render();
  } catch (error) {
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
  if (!tab || !/^https?:/.test(tab.url || "")) {
    site.textContent = "Open a web page to fill a login.";
    return;
  }
  say("Loading…");
  await load();
  search.focus();
}

start();
