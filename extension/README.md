# VisiPass browser extension

Fills logins from VisiPass in Chrome, Chromium and Brave.

- Click the toolbar icon for the logins saved for this site (exact host first), or search. Enter or a click fills.
- `Ctrl+Shift+L` on a login page fills the best match.
- The first fill of a login on a site asks you in a VisiPass window; you can make it standing.
- A login only fills on its own site. Filling it elsewhere needs "Fill anyway" and your confirmation every time.
- The extension has no standing access to pages: it runs only on the tab you act on (`activeTab`).

## Load it unpacked

1. `vp browser install` (registers the native-messaging host and prints this folder's path).
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, and choose this folder.

The extension ID is fixed by the public key in `manifest.json`: `pmfmecknoobmojibgpbkpeckpdnmhnpm`.
