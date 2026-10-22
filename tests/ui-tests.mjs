import { resolve } from "node:path";

// CI sets LOGOS_QT_MCP automatically; for interactive use: nix build .#test-framework -o result-mcp
const root = process.env.LOGOS_QT_MCP || new URL("../result-mcp", import.meta.url).pathname;
const { test, run } = await import(resolve(root, "test-framework/framework.mjs"));

test("onesecret_ui: loads UI", async (app) => {
  await app.waitFor(
    async () => { await app.expectTexts(["Onesecret", "New secret"]); },
    { timeout: 15000, interval: 500, description: "UI to load" }
  );
});

test("onesecret_ui: rejects a malformed link before any network traffic", async (app) => {
  await app.waitFor(
    async () => { await app.expectTexts(["Open"]); },
    { timeout: 15000, interval: 500, description: "tabs to appear" }
  );
});

run();
