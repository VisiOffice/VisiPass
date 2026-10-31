# visipass.app

The homepage: Astro, static, served by a Cloudflare Worker with static assets.

```sh
npm install
npm run dev       # http://localhost:4321
npm run build     # dist/
```

Deploys: Cloudflare Workers Builds connected to this repo, with root directory `site`,
build command `npm run build` and deploy command `npx wrangler deploy` (config in
`wrangler.jsonc`). Every push to main deploys.

The demos copy the product, so keep them in step with it:

- `AgentDemo.astro`: the approval window (`crates/vp-gui/src/bin/visipass-prompt/view.rs`), the
  denial message, `vp find` output and the access-log chain (`crates/vp-daemon/src/log.rs`).
- `MaskPlayground.astro`: `crates/vp-core/src/mask.rs`.
- `BrowserDemo.astro`: the extension's menu (`extension/inline.js`) and the generator
  (`crates/vp-core/src/generate.rs`).
