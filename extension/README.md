# VisiPass browser extension

Fills logins from VisiPass in Chrome, Chromium and Brave.

- Focus a login field: a VisiPass mark appears in it and a "Log in as…" menu lists the logins saved for this site. Click one, or use ↓/↑ and Enter; Esc dismisses it for that field.
- Click the toolbar icon for the same list, or to search every login. Enter or a click fills.
- `Ctrl+Shift+L` on a login page fills the best match.
- The first fill of a login on a site asks you in a VisiPass window; you can make it standing.
- A login only fills on its own site. Filling it elsewhere needs "Fill anyway" and your confirmation every time.
- On a sign-up or new-password field the menu suggests a strong password. Choosing it saves a new login for the site straight away (so a failed sign-up never loses it) and fills the password and its confirmation; when you submit the form, VisiPass adds the username the form took.
- When you submit a login form with a password VisiPass doesn't have, a card at the top right offers to save it (pick the vault, or "Never for this site"). If the password differs from the saved one for that username, it offers to update it; updating asks in the VisiPass window every time. A two-page login (username, then password) is saved with the username from the first page.
- On a two-factor code field the menu lists the site's logins and fills the current code.
- Click a login in the toolbar popup for its details: username, password (Show, Copy), the live two-factor code, other fields, websites and notes, with Fill and a favourite star. **Edit** changes any of them, adds websites and custom text or hidden fields, sets the two-factor secret (otpauth:// link or setup key), generates a password, or moves the login to the archive (restore it from the app). **+** in the header adds a new login for the current site. Like the desktop app, the popup shows values and saves changes without asking: no website can reach it.
- To add a two-factor code from a site's setup page, open the login's details in the popup and choose **+ Add a two-factor code from this page**: VisiPass reads the QR code from a screenshot of the visible tab, asks before saving it, then shows the current code on the page so you can finish setup.
- To draw the inline menu the extension runs on every http(s) page (the same access other password managers' extensions have). The menu lives in a closed shadow root, so the page cannot read it, and it holds titles and usernames only. Values are fetched when you pick a login, after VisiPass approves the site, and filled only into the frame you picked it in.
- Fills run in the background worker, so approving in the VisiPass window (which closes the toolbar popup) still completes the fill.

## Load it unpacked

1. `vp browser install` (registers the native-messaging host and prints this folder's path).
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, and choose this folder.

The extension ID is fixed by the public key in `manifest.json`: `pmfmecknoobmojibgpbkpeckpdnmhnpm`.
