# VisiPass browser extension

Fills logins from VisiPass in Chrome, Chromium and Brave.

- Focus a login field: a VisiPass mark appears in it and a "Log in as…" menu lists the logins saved for this site. Click one, or use ↓/↑ and Enter; Esc dismisses it for that field.
- Click the toolbar icon for the same list, or to search every login. Enter or a click fills.
- `Ctrl+Shift+L` on a login page fills the best match.
- The first fill of a login on a site asks you in a VisiPass window; you can make it standing.
- A login only fills on its own site. Filling it elsewhere needs "Fill anyway" and your confirmation every time.
- To draw the inline menu the extension runs on every http(s) page (the same access other password managers' extensions have). The menu lives in a closed shadow root, so the page cannot read it, and it holds titles and usernames only. Values are fetched when you pick a login, after VisiPass approves the site, and filled only into the frame you picked it in.
- Fills run in the background worker, so approving in the VisiPass window (which closes the toolbar popup) still completes the fill.

## Load it unpacked

1. `vp browser install` (registers the native-messaging host and prints this folder's path).
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, and choose this folder.

The extension ID is fixed by the public key in `manifest.json`: `pmfmecknoobmojibgpbkpeckpdnmhnpm`.
