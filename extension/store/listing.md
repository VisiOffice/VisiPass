# Chrome Web Store listing

What goes into each field of the developer dashboard. Plain text: the store does not render Markdown,
so paste the text inside each block as it is. Keep this file in step with the extension; a new
permission or data use needs its justification here before it ships.

## Store listing

**Name** (from the manifest): VisiPass

**Summary** (from the manifest's `description`, 132 characters at most):

```
Fill, suggest and save logins, two-factor codes and passkeys from VisiPass. Fills only on the login's own site.
```

**Category:** Productivity → Tools

**Language:** English

**Description:**

```
VisiPass is a password manager that runs on your computer, built so coding agents can use your credentials without ever seeing them. This extension brings your VisiPass logins into Chrome.

Requires the VisiPass app on your computer. The extension talks only to VisiPass on your machine, through Chrome's native messaging; it does nothing on its own. Install VisiPass from https://visipass.app, then run "vp browser install" once.

In the browser
• Focus a login field and a "Log in as…" menu lists the logins saved for that site. Pick one and it fills.
• A login fills only on its own site. Filling it anywhere else needs "Fill anyway" and your confirmation every time, so a look-alike phishing page gets nothing.
• On a sign-up form, VisiPass suggests a strong password and saves the login as soon as you use it.
• When you sign in with a password VisiPass doesn't have, a card offers to save it. Changing a saved password asks you first.
• Two-factor codes fill from the same menu, and can be added from a site's setup QR code.
• Passkeys: save them when a site offers to create one, and sign in with them from the same menu.
• The toolbar popup searches every login and shows, edits and adds them.
• Ctrl+Shift+L fills the best login for the page.

Privacy
• No account, no VisiPass server, no analytics. The extension makes no requests to the internet.
• Your vault is encrypted on your computer; values reach the page only when you pick a login.
• The menu lives where the page cannot read it, and holds only titles and usernames.
• Site icons come from Chrome's own cache, so no outside service learns which sites you use.

VisiPass is open source: https://github.com/VisiOffice/VisiPass
```

**Icon:** `icons/visipass-128.png`

**Screenshots** (1280×800, from the demo vault, never a real one):

1. The inline "Log in as…" menu on a login page.
2. The toolbar popup: logins on the left, one login's details on the right.
3. The save card after signing in with a new password.
4. A strong password suggested on a sign-up form.
5. The "Fill anyway" warning on a site the login isn't saved for.

**Small promo tile** (440×280): the VisiPass mark and "Passwords for you and your coding agents".

**Homepage URL:** https://visipass.app

**Support URL:** https://github.com/VisiOffice/VisiPass/issues

## Privacy practices

**Single purpose:**

```
Fill, save and generate website logins, two-factor codes and passkeys from the VisiPass password manager installed on the user's computer.
```

**Permission justifications:**

| Permission | Justification |
|---|---|
| `nativeMessaging` | The vault lives in the VisiPass app on the user's computer. Native messaging to that app (`com.visioffice.visipass`) is the extension's only way to list, fill and save logins. It talks to nothing else. |
| `activeTab` | Filling from the toolbar popup or the keyboard shortcut acts on the tab the user is on. Adding a two-factor code captures the visible tab, only when the user clicks to do so, so VisiPass can read the setup QR code. |
| `scripting` | Puts the chosen login's username and password into the login form, in the frame the user picked it in, after the user picks it in the popup or presses the shortcut. |
| `storage` | Keeps three settings (whether the menu stays quiet, sites where saving is never offered, the vault new logins go to). A password the user submits is held in session storage, which pages can't reach and which clears when the browser closes, until the user saves or dismisses the offer to save it. |
| `favicon` | Shows site icons next to logins from Chrome's own icon cache, so no request leaves the browser to fetch them. |
| Host permissions (`http://*/*`, `https://*/*`) | Login, sign-up and two-factor fields can be on any website. The content script shows the "Log in as…" menu in those fields, offers to save a login after the user submits a form, and handles a site's passkey requests. This is the same access other password managers' extensions have. Logins fill only on the site they were saved for. |

**Remote code:** No. All JavaScript is in the package.

**Data usage** (tick these):

- **Authentication information**: passwords, usernames, two-factor codes and passkeys, passed between the page and VisiPass on the user's computer.
- **Website content**: the login fields on the page and, when the user asks, a screenshot of the visible tab to read a QR code.
- **Web history**: the address of the current page, used to find that site's logins and to fill only that site. Only the current page; no browsing history is kept.

Certify all three: data is not sold, not used for anything unrelated to the single purpose, and not used for creditworthiness or lending.

**Privacy policy URL:** https://visipass.app/privacy

## Test instructions (for the reviewer)

```
The extension needs the VisiPass app on the computer; without it, the popup says "VisiPass is not connected. Run `vp browser install`, then reload this extension."

Linux (x86_64, a graphical session): download visipass-<version>-linux-x86_64.tar.gz from the newest release at https://github.com/VisiOffice/VisiPass/releases, unpack it, and put its four programs (vp, visipassd, visipass-prompt, visipass-app) together in one folder on PATH. Then:
  vp init                 # choose a master password; VisiPass shows a Secret Key, keep it
  vp browser install      # registers VisiPass with Chrome
  vp app                  # open the app and add a login for https://example.com
Load a page with a login form on that site and focus the username field: the "Log in as…" menu appears.

A screen recording of the same steps: <link>
```
