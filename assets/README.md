Brand marks, drawn on the VisiGrid construction grid (512 units, 56-unit gutters,
45° chamfers, outer radius 76; app tiles are `#101014` with the mark at 76%).

- `brand/visipass.svg`, `brand/visipass-mark.svg`: VisiPass, a block with a keyhole.
- `brand/visioffice.svg`, `brand/visioffice-mark.svg`: VisiOffice, three slabs, one per product family.
- `icons/visipass-<size>.png`: hicolor icon-theme sizes for the desktop launcher.

The `-mark` files use `currentColor`, for one-colour use (tray, docs, light backgrounds).
- `brand/visipass-extension.svg` (48, 128 px) and `-extension-small.svg` (16, 32 px): the browser extension's icons, the light block on a transparent background with a smaller keyhole than the app icon so it has room at toolbar sizes; the large sizes add Chrome's 96-of-128 margin. `icons/visipass-dark-*.png` in the extension is the same with `#101014` for light toolbars (the extension switches with the browser's colour scheme). Render with `rsvg-convert -w N -h N`.
