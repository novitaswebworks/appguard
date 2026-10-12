// Exercises React in a real browser with mocked Tauri IPC. Native enforcement
// and Rust authorization are covered separately; this is a UI contract test.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { chromium } from "playwright";
import { createServer } from "vite";

let server, browser, baseUrl;
before(async () => {
  server = await createServer({ server: { host: "127.0.0.1", port: 0, strictPort: false } });
  await server.listen();
  baseUrl = server.resolvedUrls.local[0];
  browser = await chromium.launch();
});
after(async () => { await browser?.close(); await server?.close(); });

async function openApp(t, options = {}) {
  const page = await browser.newPage({ viewport: options.label === "auth" ? { width: 360, height: 300 } : { width: 960, height: 680 } });
  t.after(() => page.close());
  await page.route("https://api.github.com/**", (route) => route.fulfill({ status: 200, json: options.release || { tag_name: "v0.7.1" } }));
  await page.addInitScript(({ label = "main", error = null, arch = "x86_64" } = {}) => {
    const callbacks = new Map(), events = new Map();
    let sequence = 0, authenticated = false;
    const calls = [];
    const target = { bundle_id: "fixture.editor", name: "Fixture Editor", request_id: 42 };
    const config = { locked_apps: {}, locked_folders: [], grace_period_seconds: 60, app_self_locked: true, pin_configured: true };
    const controls = window.testControls = {
      calls, target, holdAuth: false, holdReads: false, pending: [],
      release: () => controls.pending.splice(0).forEach((resolve) => resolve()),
      emit: (name, payload) => {
        if (name === "sessions-locked") authenticated = false;
        for (const id of events.get(name) || []) callbacks.get(id)?.({ event: name, payload });
      },
    };
    window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: (_, id) => callbacks.delete(id) };
    window.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label }, currentWebview: { label } },
      transformCallback: (handler) => { callbacks.set(++sequence, handler); return sequence; },
      invoke: async (cmd, args = {}) => {
        calls.push({ cmd, args });
        if (cmd === "plugin:event|listen") {
          events.set(args.event, [...events.get(args.event) || [], args.handler]); return args.handler;
        }
        if (cmd === "plugin:event|unlisten") return;
        if (cmd === "plugin:app|version") return "0.7.1";
        if (cmd === "plugin:autostart|is_enabled") return false;
        if (cmd === "plugin:opener|open_url") return;
        if (cmd === "check_biometrics") return { is_available: false, biometric_type: "None" };
        if (cmd === "security_status") return { error, authenticated, pin_configured: true, platform: "linux", arch, protection: { available: true, message: "Fixture window shield" } };
        if (cmd === "get_locked_app_target") return { ...controls.target };
        if (cmd === "verify_pin") { authenticated = args.pin === "1234"; return authenticated; }
        if (cmd === "authenticate_target") {
          if (controls.holdAuth) await new Promise((resolve) => controls.pending.push(resolve));
          if (args.requestId !== controls.target.request_id) throw new Error("Authentication target changed; try again");
          return args.pin === "1234";
        }
        if (["unlock_app_session", "close_locked_application"].includes(cmd)) {
          assertTarget(args); return true;
        }
        if (cmd === "hide_auth_window") return true;
        if (["get_config", "get_installed_apps", "inspect_folder_vaults", "get_activity_log", "generate_recovery_key"].includes(cmd)) {
          if (!authenticated) throw new Error("Unauthorized fixture request");
          if (controls.holdReads) await new Promise((resolve) => controls.pending.push(resolve));
          if (cmd === "get_config") return config;
          if (cmd === "get_installed_apps") return [{ name: "Fixture Editor", bundle_id: "fixture.editor", path: "/fixture" }];
          if (cmd === "generate_recovery_key") {
            if (args.pin !== "1234") throw new Error("Incorrect Master PIN");
            return "AG-TEST-ONLY-KEY2";
          }
          return [];
        }
        throw new Error(`Unexpected IPC command: ${cmd}`);
      },
    };
    function assertTarget(args) {
      if (args.bundleId !== controls.target.bundle_id || args.requestId !== controls.target.request_id) throw new Error("Wrong target");
    }
  }, options);
  await page.goto(baseUrl);
  return page;
}

test("locked startup defers dashboard reads and authenticates before loading", async (t) => {
  const page = await openApp(t);
  await page.getByRole("dialog", { name: "Unlock AppGuard", exact: true }).waitFor();
  const calls = await page.evaluate(() => window.testControls.calls);
  assert.equal(calls.some(({ cmd }) => ["get_config", "get_installed_apps", "inspect_folder_vaults", "get_activity_log"].includes(cmd)), false);
  assert.equal(await page.locator("main").getAttribute("inert"), "");
  await page.getByRole("textbox", { name: "Master PIN", exact: true }).fill("1234");
  await page.getByRole("button", { name: "Unlock AppGuard", exact: true }).click();
  await page.getByText("Fixture Editor", { exact: true }).waitFor();
  assert.equal(await page.getByRole("dialog", { name: "Unlock AppGuard", exact: true }).count(), 0);
});

test("Lock All invalidates an in-flight dashboard load", async (t) => {
  const page = await openApp(t);
  await page.getByRole("textbox", { name: "Master PIN", exact: true }).fill("1234");
  await page.evaluate(() => { window.testControls.holdReads = true; });
  await page.getByRole("button", { name: "Unlock AppGuard", exact: true }).click();
  await page.waitForFunction(() => window.testControls.pending.length === 4);
  await page.evaluate(() => { window.testControls.emit("sessions-locked", null); window.testControls.release(); });
  await page.getByRole("dialog", { name: "Unlock AppGuard", exact: true }).waitFor();
  assert.equal(await page.getByText("Fixture Editor", { exact: true }).count(), 0);
});

test("recovery enrollment requires an explicit PIN and reports rejection inline", async (t) => {
  const page = await openApp(t);
  await page.getByRole("textbox", { name: "Master PIN", exact: true }).fill("1234");
  await page.getByRole("button", { name: "Unlock AppGuard", exact: true }).click();
  await page.getByText("Fixture Editor", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Security & Settings" }).click();
  await page.getByRole("button", { name: "Generate Key", exact: true }).click();
  assert.equal(await page.evaluate(() => window.testControls.calls.some(({ cmd }) => cmd === "generate_recovery_key")), false);
  await page.getByLabel("Master PIN for recovery enrollment").fill("9999");
  await page.getByRole("button", { name: "Generate key", exact: true }).click();
  await page.getByRole("alert").filter({ hasText: "Incorrect Master PIN" }).waitFor();
  await page.getByLabel("Master PIN for recovery enrollment").fill("1234");
  await page.getByRole("button", { name: "Generate key", exact: true }).click();
  await page.getByText("AG-TEST-ONLY-KEY2", { exact: true }).waitFor();
  await page.evaluate(() => window.testControls.emit("sessions-locked", null));
  await page.getByRole("dialog", { name: "Unlock AppGuard", exact: true }).waitFor();
  assert.equal(await page.getByText("AG-TEST-ONLY-KEY2", { exact: true }).count(), 0);
});

test("configuration failure displays a blocked startup instead of onboarding", async (t) => {
  const page = await openApp(t, { error: "Configuration is damaged" });
  await page.getByText("AppGuard needs attention", { exact: true }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Finish Setup" }).count(), 0);
  assert.equal(await page.getByRole("textbox").count(), 0);
});

test("updates select the native architecture and reject foreign release links", async (t) => {
  const prefix = "https://github.com/novitaswebworks/appguard/releases/download/v9.0.0/";
  const page = await openApp(t, { arch: "aarch64", release: {
    tag_name: "v9.0.0", html_url: "https://example.invalid/redirect",
    assets: [
      { name: "malicious_aarch64.AppImage", browser_download_url: "https://example.invalid/payload", size: 12 },
      ...["AppGuard_9.0.0_amd64.deb", "AppGuard_9.0.0_amd64.AppImage", "AppGuard_9.0.0_aarch64.AppImage"].map((name) => ({ name, browser_download_url: prefix + name, size: 1024 })),
    ],
  } });
  await page.getByRole("textbox", { name: "Master PIN", exact: true }).fill("1234");
  await page.getByRole("button", { name: "Unlock AppGuard", exact: true }).click();
  await page.getByRole("button", { name: "Download AppGuard_9.0.0_aarch64.AppImage", exact: true }).click();
  await page.getByRole("button", { name: "View Release", exact: true }).click();
  const urls = await page.evaluate(() => window.testControls.calls.filter(({ cmd }) => cmd === "plugin:opener|open_url").map(({ args }) => args.url));
  assert.deepEqual(urls, [prefix + "AppGuard_9.0.0_aarch64.AppImage", "https://github.com/novitaswebworks/appguard/releases/latest"]);
});

test("compact authentication keeps input on duplicate events and sends the bound request", async (t) => {
  const page = await openApp(t, { label: "auth" });
  await page.getByRole("heading", { name: "Fixture Editor" }).waitFor();
  const pin = page.getByRole("textbox", { name: "Master PIN", exact: true });
  await pin.fill("1234");
  await page.evaluate(() => window.testControls.emit("app-locked-triggered", { ...window.testControls.target }));
  assert.equal(await pin.inputValue(), "1234");
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await page.waitForFunction(() => window.testControls.calls.some(({ cmd }) => cmd === "unlock_app_session"));
  const calls = await page.evaluate(() => window.testControls.calls);
  assert.equal(calls.some(({ cmd }) => ["verify_pin", "authenticate_biometrics"].includes(cmd)), false);
  assert.deepEqual(calls.find(({ cmd }) => cmd === "unlock_app_session").args, { bundleId: "fixture.editor", requestId: 42, durationSecs: null });
});

test("changing a challenge during verification cannot unlock the replacement", async (t) => {
  const page = await openApp(t, { label: "auth" });
  await page.getByRole("heading", { name: "Fixture Editor" }).waitFor();
  await page.evaluate(() => { window.testControls.holdAuth = true; });
  await page.getByRole("textbox", { name: "Master PIN", exact: true }).fill("1234");
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await page.waitForFunction(() => window.testControls.pending.length === 1);
  await page.evaluate(() => {
    window.testControls.target = { bundle_id: "fixture.second", name: "Second Editor", request_id: 43 };
    window.testControls.emit("app-locked-triggered", window.testControls.target);
  });
  await page.getByRole("heading", { name: "Second Editor" }).waitFor();
  await page.evaluate(() => window.testControls.release());
  await page.getByRole("alert").waitFor();
  assert.equal(await page.evaluate(() => window.testControls.calls.some(({ cmd }) => cmd === "unlock_app_session")), false);
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  const calls = await page.evaluate(() => window.testControls.calls);
  assert.deepEqual(calls.find(({ cmd }) => cmd === "close_locked_application").args, { bundleId: "fixture.second", requestId: 43 });
});
