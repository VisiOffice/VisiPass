import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { generateKeyPairSync } from "node:crypto";
import { defineConfig } from "vitest/config";

// A throwaway APNs key, so the tests sign real provider tokens.
const apnsKey = generateKeyPairSync("ec", { namedCurve: "P-256" })
  .privateKey.export({ type: "pkcs8", format: "pem" })
  .toString();

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: { APNS_KEY: apnsKey, APNS_KEY_ID: "KEYID12345", APNS_TEAM_ID: "TEAM123456", REPLY_MS: "300" },
      },
    }),
  ],
});
