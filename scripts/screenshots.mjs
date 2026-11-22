#!/usr/bin/env node
// Takes the screenshots in docs/screenshots: the window with the sample
// data of the browser preview, in light and in dark, at twice its size, in
// a macOS window frame with a shadow on a transparent background. The
// sample is the one with SSL/TLS certificates only (`?sample=web`). No
// YubiKey is involved and nothing of a real workspace shows.
//
//   npm --prefix app run dev                 # in another terminal
//   node scripts/screenshots.mjs [scene ...]
//
// It drives Google Chrome without a window through its DevTools protocol;
// CHROME names another Chrome or Chromium to use. Without scenes it takes
// them all.

import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "docs", "screenshots");
const only = process.argv.slice(2);
const chromePath =
  process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const app = "http://localhost:1420";
const port = 9333;

// The window at the size the app opens with, and the room around it for
// the shadow.
const width = 1280;
const height = 800;
const margin = 56;

const pause = (ms) => new Promise((done) => setTimeout(done, ms));

mkdirSync(out, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "yca-screenshots-"));
const chrome = spawn(
  chromePath,
  [
    "--headless=new",
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${profile}`,
    "--hide-scrollbars",
    "--force-color-profile=srgb",
    "--no-first-run",
    "--no-default-browser-check",
    "about:blank",
  ],
  { stdio: "ignore" },
);

let target;
for (let tries = 0; tries < 50 && !target; tries++) {
  await pause(200);
  try {
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    target = targets.find((each) => each.type === "page");
  } catch {
    // Not up yet.
  }
}
if (!target) throw new Error(`Chrome did not start: ${chromePath}`);

const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((done) => socket.addEventListener("open", done, { once: true }));
let lastId = 0;
const pending = new Map();
socket.addEventListener("message", (event) => {
  const message = JSON.parse(event.data);
  const call = pending.get(message.id);
  if (!call) return;
  pending.delete(message.id);
  if (message.error) call.reject(new Error(JSON.stringify(message.error)));
  else call.resolve(message.result);
});
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++lastId;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
}

/** Runs code in the page and waits for it. */
async function run(code) {
  const result = await send("Runtime.evaluate", {
    expression: `(async () => { ${code} })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text);
  }
  return result.result.value;
}

// What the scenes do in the page: wait, click what says something, type.
const helpers = `
  window.wait = (ms) => new Promise((done) => setTimeout(done, ms));
  window.click = async (text, selector = "button, [role=menuitem]") => {
    for (let tries = 0; tries < 40; tries++) {
      const found = [...document.querySelectorAll(selector)]
        .find((each) => each.textContent.trim().includes(text));
      if (found) return found.click();
      await wait(100);
    }
    throw new Error("nothing says " + text);
  };
  window.type = (input, value) => {
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    set.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  };
  window.openMenu = (button) => button.dispatchEvent(
    new PointerEvent("pointerdown", { bubbles: true, button: 0, pointerType: "mouse" }));
`;

/** Loads the window in a colour scheme, with the sample workspace open. */
async function load(path, scheme) {
  await send("Emulation.setDeviceMetricsOverride", {
    width,
    height,
    deviceScaleFactor: 2,
    mobile: false,
  });
  await send("Emulation.setEmulatedMedia", {
    features: [{ name: "prefers-color-scheme", value: scheme }],
  });
  await send("Emulation.setDefaultBackgroundColorOverride", {});
  // From the start, with no workspace remembered; opened once, the sample
  // workspace then opens again with every load.
  await send("Page.navigate", { url: app });
  await pause(800);
  await run("localStorage.clear();");
  await send("Page.navigate", { url: app });
  await pause(1200);
  await run(`${helpers} await click("Open existing workspace"); await wait(600);`);
  await send("Page.navigate", { url: app + path });
  await pause(1500);
  await run(helpers);
}

async function capture() {
  await run("document.activeElement?.blur?.(); await wait(500);");
  const { data } = await send("Page.captureScreenshot", { format: "png" });
  return data;
}

/** The window with rounded corners, its three buttons and its shadow. */
async function framed(png, scheme) {
  const edge = scheme === "dark" ? "rgba(255,255,255,0.16)" : "rgba(0,0,0,0.22)";
  const html = `<!doctype html><html><head><style>
    html, body { margin: 0; background: transparent; }
    .window { position: absolute; left: ${margin}px; top: ${margin - 12}px;
      width: ${width}px; height: ${height}px; border-radius: 16px; overflow: hidden;
      box-shadow: 0 0 0 0.5px ${edge}, 0 22px 48px rgba(0,0,0,0.32), 0 4px 12px rgba(0,0,0,0.16); }
    .window img { display: block; width: ${width}px; height: ${height}px; }
    .button { position: absolute; top: 15px; width: 12px; height: 12px; border-radius: 50%;
      box-shadow: inset 0 0 0 0.5px rgba(0,0,0,0.18); }
  </style></head><body><div class="window"><img src="data:image/png;base64,${png}">
    <span class="button" style="left: 16px; background: #ff5f57"></span>
    <span class="button" style="left: 36px; background: #febc2e"></span>
    <span class="button" style="left: 56px; background: #28c840"></span>
  </div></body></html>`;
  await send("Emulation.setDeviceMetricsOverride", {
    width: width + 2 * margin,
    height: height + 2 * margin,
    deviceScaleFactor: 2,
    mobile: false,
  });
  await send("Emulation.setDefaultBackgroundColorOverride", {
    color: { r: 0, g: 0, b: 0, a: 0 },
  });
  await send("Page.navigate", {
    url: "data:text/html;base64," + Buffer.from(html).toString("base64"),
  });
  await pause(600);
  const { data } = await send("Page.captureScreenshot", { format: "png" });
  return data;
}

const scenes = {
  // The certificates of a workspace.
  main: async (scheme) => {
    await load("/?sample=web", scheme);
    return capture();
  },
  // A new certificate, by what the device's upload form asks for.
  "new-certificate": async (scheme) => {
    await load("/?sample=web", scheme);
    await run(`
      await click("New certificate");
      await wait(400);
      await click("Web server (SSL/TLS)");
      await wait(400);
      type(document.querySelector("[data-slot=dialog-content] input"), "nas.home.example, 192.168.1.20");
    `);
    return capture();
  },
  // What an AI agent asked for, put before the person.
  agent: async (scheme) => {
    await load("/?sample=web&ask=issue", scheme);
    // The options it asked for, folded away, so that the dialog fits.
    await run(`await wait(1200); await click("Options", "[data-slot=dialog-content] button"); await wait(300);`);
    return capture();
  },
  // Making devices trust the CA.
  trust: async (scheme) => {
    await load("/?sample=web", scheme);
    await run(`
      openMenu(document.querySelector("aside button[aria-label=Actions]"));
      await wait(400);
      await click("Install on your devices");
      await wait(600);
    `);
    return capture();
  },
};

try {
  for (const [name, scene] of Object.entries(scenes)) {
    if (only.length > 0 && !only.includes(name)) continue;
    for (const scheme of ["light", "dark"]) {
      const file = join(out, `${name}-${scheme}.png`);
      writeFileSync(file, Buffer.from(await framed(await scene(scheme), scheme), "base64"));
      console.log(file);
    }
  }
} finally {
  socket.close();
  chrome.kill();
  await pause(800);
  rmSync(profile, { recursive: true, force: true });
}
