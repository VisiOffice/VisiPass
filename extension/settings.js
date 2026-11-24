import { MARK, icon } from "./icons.js";
import { FEATURES, getPaused, getSettings, normalizeOrigin, setPaused, setSettings } from "./prefs.js";

const FEATURE_LABELS = {
  menu: "Menu",
  save: "Save",
  suggest: "Suggest",
  passkeys: "Passkeys",
};

const switches = {
  menu: document.getElementById("opt-menu"),
  save: document.getElementById("opt-save"),
  suggest: document.getElementById("opt-suggest"),
  passkeys: document.getElementById("opt-passkeys"),
};

const browserPmRow = document.getElementById("browser-pm-row");
const browserPmSwitch = document.getElementById("opt-browser-pm");
const browserPmDesc = document.getElementById("browser-pm-desc");

const addSiteForm = document.getElementById("add-site-form");
const siteInput = document.getElementById("site-input");
const siteError = document.getElementById("site-error");
const pausedTable = document.getElementById("paused-table");
const pausedBody = document.getElementById("paused-body");
const pausedEmpty = document.getElementById("paused-empty");

const shortcutsList = document.getElementById("shortcuts-list");
const openShortcutsBtn = document.getElementById("open-shortcuts");

const DEFAULT_PM_DESC = "Turns off your browser's built-in password saving prompts.";

let pausedState = {};
let privacyListenerAttached = false;

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text != null) node.textContent = text;
  return node;
}

// Follows the Omarchy theme when VisiPass returns one; otherwise CSS falls back
// to the system's light or dark mode.
function loadTheme() {
  chrome.runtime
    .sendMessage({ kind: "theme" })
    .then((reply) => {
      const theme = reply?.ok ? reply.result : null;
      for (const [key, value] of Object.entries(theme || {})) {
        if (!value) continue;
        const name = { background: "bg", foreground: "fg", font: "mono" }[key] || key;
        document.documentElement.style.setProperty(`--${name}`, key === "font" ? `"${value}", ui-monospace, monospace` : value);
      }
    })
    .catch(() => {});
}

// ---- Global switches ----

async function renderSettings() {
  const settings = await getSettings();
  for (const key of FEATURES) switches[key].checked = settings[key];
}

for (const key of FEATURES) {
  switches[key].addEventListener("change", () => {
    setSettings({ [key]: switches[key].checked }).catch(() => renderSettings());
  });
}

// ---- Browser password manager switch ----

function applyPrivacyState(details) {
  const { value, levelOfControl } = details;
  if (levelOfControl === "not_controllable") {
    browserPmSwitch.checked = false;
    browserPmSwitch.disabled = true;
    browserPmRow.classList.add("disabled");
    browserPmDesc.textContent = "Controlled by your browser's policy.";
    return;
  }
  if (levelOfControl === "controlled_by_other_extensions") {
    browserPmSwitch.checked = false;
    browserPmSwitch.disabled = true;
    browserPmRow.classList.add("disabled");
    browserPmDesc.textContent = "Controlled by another extension.";
    return;
  }
  browserPmSwitch.disabled = false;
  browserPmRow.classList.remove("disabled");
  browserPmSwitch.checked = levelOfControl === "controlled_by_this_extension" && value === false;
  browserPmDesc.textContent = DEFAULT_PM_DESC;
}

async function renderBrowserPm() {
  const hasPrivacy = await chrome.permissions.contains({ permissions: ["privacy"] });
  if (!hasPrivacy || !chrome.privacy?.services?.passwordSavingEnabled) {
    browserPmSwitch.checked = false;
    browserPmSwitch.disabled = false;
    browserPmRow.classList.remove("disabled");
    browserPmDesc.textContent = DEFAULT_PM_DESC;
    return;
  }
  if (!privacyListenerAttached) {
    privacyListenerAttached = true;
    chrome.privacy.services.passwordSavingEnabled.onChange.addListener(applyPrivacyState);
  }
  const details = await chrome.privacy.services.passwordSavingEnabled.get({});
  applyPrivacyState(details);
}

browserPmSwitch.addEventListener("change", () => {
  // Whatever fails, the switch ends up showing the browser's real state.
  changeBrowserPm().catch(() => renderBrowserPm().catch(() => {}));
});

async function changeBrowserPm() {
  const wantOff = browserPmSwitch.checked;
  if (wantOff) {
    // Request the optional `privacy` permission directly inside the user click.
    const granted = await chrome.permissions.request({ permissions: ["privacy"] });
    if (!granted || !chrome.privacy?.services?.passwordSavingEnabled) {
      browserPmSwitch.checked = false;
      return;
    }
    const current = await chrome.privacy.services.passwordSavingEnabled.get({});
    if (current.levelOfControl === "not_controllable" || current.levelOfControl === "controlled_by_other_extensions") {
      applyPrivacyState(current);
      return;
    }
    await chrome.privacy.services.passwordSavingEnabled.set({ value: false });
  } else if (chrome.privacy?.services?.passwordSavingEnabled) {
    await chrome.privacy.services.passwordSavingEnabled.clear({});
  }
  await renderBrowserPm();
}

// ---- Paused sites ----

function renderPaused() {
  const origins = Object.keys(pausedState).sort();
  pausedTable.hidden = origins.length === 0;
  pausedEmpty.hidden = origins.length > 0;
  pausedBody.replaceChildren(
    ...origins.map((origin) => {
      const entry = pausedState[origin];
      const tr = el("tr");
      tr.append(el("td", "site-cell", origin));
      for (const feature of FEATURES) {
        const td = el("td");
        const box = el("input");
        box.type = "checkbox";
        box.checked = Boolean(entry[feature]);
        box.setAttribute("aria-label", `Pause ${FEATURE_LABELS[feature]} on ${origin}`);
        box.addEventListener("change", async () => {
          pausedState[origin] = { ...pausedState[origin], [feature]: box.checked };
          await setPaused(pausedState);
        });
        td.append(box);
        tr.append(td);
      }
      const removeCell = el("td", "col-remove");
      const removeBtn = el("button", "iconbtn");
      removeBtn.type = "button";
      removeBtn.title = `Remove ${origin}`;
      removeBtn.setAttribute("aria-label", `Remove ${origin}`);
      removeBtn.innerHTML = icon("close");
      removeBtn.addEventListener("click", async () => {
        delete pausedState[origin];
        await setPaused(pausedState);
        renderPaused();
      });
      removeCell.append(removeBtn);
      tr.append(removeCell);
      return tr;
    }),
  );
}

async function loadPaused() {
  pausedState = await getPaused();
  renderPaused();
}

addSiteForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  siteError.textContent = "";
  const origin = normalizeOrigin(siteInput.value);
  if (!origin) {
    siteError.textContent = "Enter a valid http or https site (for example, example.com).";
    siteInput.focus();
    return;
  }
  if (pausedState[origin]) {
    siteError.textContent = `${origin} is already in the list.`;
    siteInput.focus();
    return;
  }
  pausedState[origin] = { menu: true, save: true, suggest: true, passkeys: true };
  await setPaused(pausedState);
  siteInput.value = "";
  renderPaused();
});

siteInput.addEventListener("input", () => {
  if (siteError.textContent) siteError.textContent = "";
});

// ---- Keyboard shortcuts ----

async function renderShortcuts() {
  const commands = await chrome.commands.getAll();
  shortcutsList.replaceChildren(
    ...commands.map((cmd) => {
      const row = el("div", "shortcut-row");
      const label = cmd.description || (cmd.name === "_execute_action" ? "Open VisiPass" : cmd.name);
      row.append(el("span", "", label));
      if (cmd.shortcut) row.append(el("kbd", "shortcut-key", cmd.shortcut));
      else row.append(el("span", "shortcut-none", "Not set"));
      return row;
    }),
  );
}

openShortcutsBtn.addEventListener("click", async () => {
  const isBrave = Boolean(navigator.brave && (await navigator.brave.isBrave().catch(() => false)));
  chrome.tabs.create({ url: isBrave ? "brave://extensions/shortcuts" : "chrome://extensions/shortcuts" });
});

// Keep the page in sync if another tab changes paused sites or settings.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.settings) renderSettings();
  if (changes.paused) loadPaused();
});

async function start() {
  document.getElementById("brand").innerHTML = MARK;
  loadTheme();
  await Promise.all([renderSettings(), renderBrowserPm(), loadPaused(), renderShortcuts()]);
}

start();
