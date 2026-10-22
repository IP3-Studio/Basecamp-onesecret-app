#!/usr/bin/env node
// Two-party protocol test. Launches two isolated instances of the standalone
// dev host (A = sender, B = recipient), drives both through the QML inspector
// (logos-qt-mcp, newline-delimited JSON over TCP) and checks the protocol end
// to end, including the store catch-up paths where one side is offline.
//
//   ONESECRET_RUN=./result-ui-dev/bin/run-logos-standalone-ui \
//   ONESECRET_QML=$PWD/src/qml  ONESECRET_WORK=/path/to/workdir \
//   node tests/two-party.mjs [--keep]
//
// Each instance gets its own HOME, so every Qt standard path (and the delivery
// module's persistence) is separate. Screenshots and logs land in WORK.

import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import { spawn, execSync } from "node:child_process";

const RUN = process.env.ONESECRET_RUN;
const QML = process.env.ONESECRET_QML || "";
const WORK = process.env.ONESECRET_WORK || path.resolve("two-party-work");
const KEEP = process.argv.includes("--keep");
const PRESET = process.env.ONESECRET_PRESET || "logos.dev";
if (!RUN) { console.error("ONESECRET_RUN is required"); process.exit(2); }
fs.mkdirSync(WORK, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const stamp = () => new Date().toISOString().slice(11, 19);
const log = (...a) => console.log(`[${stamp()}]`, ...a);

class Inspector {
  constructor(port) { this.port = port; this.sock = null; this.id = 0; this.pending = new Map(); this.buf = ""; }
  async connect(timeoutMs = 60000) {
    const start = Date.now();
    for (;;) {
      try {
        await new Promise((res, rej) => {
          const s = net.createConnection({ host: "127.0.0.1", port: this.port });
          s.once("connect", () => { this.sock = s; res(); });
          s.once("error", rej);
          s.on("data", (c) => { this.buf += c.toString("utf-8"); this._drain(); });
          s.on("close", () => { this.sock = null; for (const [, p] of this.pending) p.reject(new Error("closed")); this.pending.clear(); });
        });
        return;
      } catch (e) {
        if (Date.now() - start > timeoutMs) throw new Error(`inspector :${this.port} not reachable: ${e.message}`);
        await sleep(500);
      }
    }
  }
  _drain() {
    let i;
    while ((i = this.buf.indexOf("\n")) !== -1) {
      const line = this.buf.slice(0, i).trim(); this.buf = this.buf.slice(i + 1);
      if (!line) continue;
      try { const m = JSON.parse(line); const p = this.pending.get(String(m.id)); if (p) { clearTimeout(p.t); this.pending.delete(String(m.id)); p.resolve(m); } } catch {}
    }
  }
  send(command, params = {}) {
    if (!this.sock) return Promise.reject(new Error("not connected"));
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.pending.delete(String(id)); reject(new Error(`timeout ${command}`)); }, 20000);
      this.pending.set(String(id), { resolve, reject, t });
      this.sock.write(JSON.stringify({ id, command, params }) + "\n");
    });
  }
  close() { if (this.sock) this.sock.destroy(); }
}

class Peer {
  constructor(name, port) {
    this.name = name; this.port = port;
    this.home = path.join(WORK, `home-${name}`);
    // Passed explicitly as --user-dir and LOGOS_USER_DIR, so the same short
    // path works on macOS and Linux.
    this.userDir = path.join(this.home, "basecamp");
    this.logPath = path.join(WORK, `${name}.log`);
    this.proc = null; this.insp = null; this.launches = 0;
  }
  async start() {
    fs.mkdirSync(this.home, { recursive: true });
    const env = {
      ...process.env,
      HOME: this.home,
      LOGOS_USER_DIR: this.userDir,
      QML_INSPECTOR_PORT: String(this.port),
      QT_QPA_PLATFORM: process.env.ONESECRET_PLATFORM || "offscreen",
    };
    if (QML) env.DEV_QML_PATH = QML; else env.LOGOS_QML_HOT_RELOAD = "0";
    const out = fs.openSync(this.logPath, "a");
    fs.writeSync(out, `\n===== launch ${++this.launches} at ${new Date().toISOString()} =====\n`);
    // detached: own process group, so stop() can take down the ui-host backend
    // and the delivery node host as well, not only the shell window.
    this.proc = spawn(RUN, ["--user-dir", this.userDir], { env, stdio: ["ignore", out, out], cwd: WORK, detached: true });
    this.proc.on("exit", (code, sig) => { log(`${this.name}: process exited code=${code} sig=${sig}`); this.proc = null; });
    this.insp = new Inspector(this.port);
    await this.insp.connect(90000);
    await this.waitFor(async () => (await this.rootProp("ready")) === true, 60000, `${this.name} backend ready`);
    log(`${this.name}: up (launch ${this.launches})`);
  }
  _children() {
    // Every process launched for this instance carries its user dir on the
    // command line (logos_host --instance-persistence-path …) or inherits it.
    try {
      // "[/]home/..." matches the real paths but not the shell running this
      // very pgrep, whose command line carries the bracketed pattern.
      const pattern = this.userDir.replace(/^(.)/, "[$1]");
      const out = execSync(`pgrep -f ${JSON.stringify(pattern)} || true`, { encoding: "utf-8" });
      return out.split("\n").map((x) => parseInt(x, 10)).filter((n) => Number.isFinite(n) && n !== process.pid);
    } catch { return []; }
  }
  async stop() {
    if (this.insp) { this.insp.close(); this.insp = null; }
    const p = this.proc;
    if (p && p.pid) {
      try { process.kill(-p.pid, "SIGTERM"); } catch { try { p.kill("SIGTERM"); } catch {} }
      await Promise.race([new Promise((r) => p.once("exit", r)), sleep(8000)]);
    }
    // Make sure nothing of this instance survives: a lingering backend would
    // keep answering claims and void the offline scenarios.
    for (let i = 0; i < 20; i++) {
      const kids = this._children();
      if (!kids.length) break;
      for (const pid of kids) { try { process.kill(pid, i < 5 ? "SIGTERM" : "SIGKILL"); } catch {} }
      await sleep(500);
    }
    const left = this._children();
    if (left.length) throw new Error(`${this.name}: processes still alive after stop: ${left.join(",")}`);
    this.proc = null;
    log(`${this.name}: stopped (and all of its processes)`);
  }
  async find(objectName) {
    const r = await this.insp.send("findByProperty", { property: "objectName", value: objectName });
    if (r.error || !r.matches || !r.matches.length) throw new Error(`${this.name}: no object "${objectName}"`);
    if (r.matches.length === 1) return r.matches[0].id;
    // Several instances (list rows): prefer the one that is actually visible.
    for (const m of r.matches) {
      const p = await this.insp.send("getProperties", { objectId: m.id });
      const vis = (p.properties || []).find((x) => x.name === "visible");
      if (vis && vis.value === true) return m.id;
    }
    return r.matches[0].id;
  }
  async props(objectName) {
    const id = await this.find(objectName);
    const r = await this.insp.send("getProperties", { objectId: id });
    if (r.error) throw new Error(`${this.name}: getProperties(${objectName}): ${r.error}`);
    const o = {};
    for (const p of r.properties || []) o[p.name] = p.value;
    return o;
  }
  async prop(objectName, name) { return (await this.props(objectName))[name]; }
  async rootProp(name) { return this.prop("onesecretRoot", name); }
  async set(objectName, property, value) {
    const id = await this.find(objectName);
    const r = await this.insp.send("setProperty", { objectId: id, property, value });
    if (r.error) throw new Error(`${this.name}: set ${objectName}.${property}: ${r.error}`);
  }
  async click(objectName) {
    const id = await this.find(objectName);
    const r = await this.insp.send("click", { objectId: id });
    if (r.error) throw new Error(`${this.name}: click ${objectName}: ${r.error}`);
  }
  async screenshot(label) {
    try {
      const r = await this.insp.send("screenshot", {});
      if (r.image) fs.writeFileSync(path.join(WORK, `${this.name}-${label}.png`), Buffer.from(r.image, "base64"));
    } catch (e) { log(`${this.name}: screenshot failed: ${e.message}`); }
  }
  async waitFor(fn, timeoutMs, desc) {
    const start = Date.now();
    let last = "";
    while (Date.now() - start < timeoutMs) {
      try { if (await fn()) return; } catch (e) { last = e.message; }
      await sleep(1000);
    }
    throw new Error(`${this.name}: timed out waiting for ${desc}${last ? ` (last: ${last})` : ""}`);
  }
  async waitDelivery() {
    await this.waitFor(async () => {
      const st = await this.rootProp("deliveryState");
      return st === "online" || st === "partial";
    }, 240000, "delivery node connected");
    log(`${this.name}: delivery ${await this.rootProp("deliveryState")}: ${await this.rootProp("deliveryInfo")}`);
  }
  async sent() { return JSON.parse(await this.rootProp("sentListJson")); }
  async tab(index) { await this.set("tabs", "currentIndex", index); await sleep(300); }
  async createSecret(name, body, pass = "") {
    await this.tab(0);
    const before = await this.rootProp("lastLink");
    if (before) { await this.click("linkDone"); await sleep(300); }
    await this.set("nameField", "text", name);
    await this.set("bodyArea", "text", body);
    await this.set("passField", "text", pass);
    await this.click("createButton");
    let link = "";
    await this.waitFor(async () => { link = await this.rootProp("lastLink"); return typeof link === "string" && link.startsWith("os1_") && link !== before; }, 15000, "a new link");
    const id = (await this.sent())[0].id;
    return { link, id };
  }
  async openLink(link, pass = "") {
    await this.tab(2);
    await this.set("linkField", "text", link);
    await this.set("openPassField", "text", pass);
    await this.click("openButton");
  }
  // Reader count: set the view's properties directly rather than clicking a
  // button that may sit below the scroll view's visible area.
  async setReaders(n) {
    await this.tab(0);
    await this.set("onesecretRoot", "readersCustom", false);
    const presets = [1, 2, 3, 5];
    const idx = presets.indexOf(n);
    if (idx >= 0) {
      await this.set("onesecretRoot", "readerIndex", idx);
    } else {
      await this.set("onesecretRoot", "customReaders", n);
      await this.set("onesecretRoot", "readersCustom", true);
    }
    const eff = await this.rootProp("effectiveReaders");
    if (eff !== n) throw new Error(`${this.name}: readers is ${eff}, wanted ${n}`);
  }
  async burnNewest() {
    await this.tab(1);
    await this.click("burnButton");
    await sleep(300);
    await this.click("burnConfirmButton");
  }
  async revealText() { return this.prop("revealBody", "text"); }
  // Replica properties arrive one at a time, so wait until the id, the state
  // and the revealed text all agree before reading anything.
  async waitOpened(id, body, timeoutMs = 60000) {
    await this.waitFor(async () => {
      const r = await this.props("onesecretRoot");
      if (r.openId !== id || r.openState !== "opened") return false;
      return (await this.revealText()) === body;
    }, timeoutMs, `${this.name} opened ${id}`);
  }
  async waitOpenState(id, state, timeoutMs = 60000) {
    await this.waitFor(async () => {
      const r = await this.props("onesecretRoot");
      return r.openId === id && r.openState === state;
    }, timeoutMs, `${this.name} state ${state} for ${id}`);
  }
}

const results = [];
async function step(name, fn) {
  log(`--- ${name}`);
  try { await fn(); results.push({ name, ok: true }); log(`PASS ${name}`); }
  catch (e) { results.push({ name, ok: false, error: e.message }); log(`FAIL ${name}: ${e.message}`); throw e; }
}

const A = new Peer("A", 3771);
const B = new Peer("B", 3772);
const C = new Peer("C", 3773);   // a third reader, started for the multi-reader steps only
const rnd = () => Math.random().toString(36).slice(2, 10);

async function smoke() {
  await A.start();
  const r = await A.props("onesecretRoot");
  for (const k of ["ready", "deliveryState", "deliveryInfo", "preset", "dataDir", "lastError", "openState"]) log(`A.${k} = ${JSON.stringify(r[k])}`);
  await A.screenshot("smoke-start");
  await A.waitDelivery().catch((e) => log(e.message));
  const r2 = await A.props("onesecretRoot");
  for (const k of ["deliveryState", "deliveryInfo", "lastError"]) log(`A.${k} = ${JSON.stringify(r2[k])}`);
  await A.screenshot("smoke-connected");
  for (const name of ["tabs", "nameField", "bodyArea", "passField", "createButton", "linkField", "openPassField", "openButton", "revealBody", "revealClose"]) {
    try { await A.find(name); } catch (e) { log(`MISSING object ${name}`); }
  }
}

async function main() {
  if (process.argv.includes("--smoke")) return smoke();
  await A.start(); await B.start();
  await A.screenshot("00-start"); await B.screenshot("00-start");
  log(`A data dir: ${await A.rootProp("dataDir")}`);
  log(`B data dir: ${await B.rootProp("dataDir")}`);
  await Promise.all([A.waitDelivery(), B.waitDelivery()]);

  let s1, s2, s3, s4, s5;
  const body1 = `hello from A ${rnd()}`;

  await step("0 expiry: presets and a custom value reach the backend", async () => {
    await A.tab(0);
    await A.click("ttlPreset3");                       // 72 hours
    const p = await A.createSecret("Seventy-two", `ttl ${rnd()}`);
    const row72 = (await A.sent()).find((x) => x.id === p.id);
    if (row72.ttlHours !== 72) throw new Error(`preset 72 h stored as ${row72.ttlHours}`);
    await A.click("ttlCustomButton");
    await A.set("customTtlField", "text", "36");
    await A.click("ttlUnitHours");
    const c = await A.createSecret("Thirty-six", `ttl ${rnd()}`);
    const row36 = (await A.sent()).find((x) => x.id === c.id);
    if (row36.ttlHours !== 36) throw new Error(`custom 36 h stored as ${row36.ttlHours}`);
    await A.set("customTtlField", "text", "5");
    await A.click("ttlUnitDays");
    const d5 = await A.createSecret("Five days", `ttl ${rnd()}`);
    const row5 = (await A.sent()).find((x) => x.id === d5.id);
    if (row5.ttlHours !== 120) throw new Error(`custom 5 days stored as ${row5.ttlHours}`);
    await A.set("customTtlField", "text", "20");       // 20 days: out of range, button must disable
    const enabled = await A.prop("createButton", "enabled");
    if (enabled !== false) throw new Error("Create link stayed enabled for an out-of-range TTL");
    await A.screenshot("00-ttl-custom");
    await A.tab(0);
    await A.click("ttlPreset1");                       // back to 24 hours for the rest
    if ((await A.rootProp("effectiveTtlHours")) !== 24) throw new Error("preset did not reset the custom value");
  });

  await step("1 online: create on A, open on B, receipt on A", async () => {
    s1 = await A.createSecret("Test one", body1);
    log(`link1 ${s1.link} id ${s1.id}`);
    await A.screenshot("01-created");
    await B.openLink(s1.link);
    await B.waitOpened(s1.id, body1, 120000);
    await B.screenshot("01-revealed");
    await A.waitFor(async () => (await A.sent()).find((x) => x.id === s1.id)?.state === "done", 60000, "A shows Opened");
    const row = (await A.sent()).find((x) => x.id === s1.id);
    if (!row.readers.length || !row.readers[0].fp) throw new Error("no device fingerprint on receipt");
    log(`A receipt: ${row.label} at ${row.readers[0].openedAt} device ${row.readers[0].fp}`);
    await A.screenshot("01-receipt");
  });

  await step("2 re-open on B is refused", async () => {
    await B.click("revealClose");
    if ((await B.revealText()) !== "") throw new Error("reveal text not cleared on close");
    await B.openLink(s1.link);
    await B.waitOpenState(s1.id, "already", 10000);
  });

  await step("3 corrupt link rejected locally", async () => {
    const bad = s1.link.slice(0, 20) + (s1.link[20] === "A" ? "B" : "A") + s1.link.slice(21);
    await B.openLink(bad);
    await B.waitFor(async () => (await B.rootProp("openState")) === "invalid", 5000, "invalid");
  });

  await step("4 passphrase: wrong rejected, right opens", async () => {
    const body = `pass-protected ${rnd()}`;
    s2 = await A.createSecret("With passphrase", body, "correct horse");
    await B.openLink(s2.link, "wrong horse");
    await B.waitOpenState(s2.id, "needs-passphrase", 120000);
    await B.screenshot("04-wrong-pass");
    await B.openLink(s2.link, "correct horse");
    await B.waitOpened(s2.id, body, 30000);
    await B.click("revealClose");
    await A.waitFor(async () => (await A.sent()).find((x) => x.id === s2.id)?.state === "done", 60000, "A shows Opened");
  });

  await step("5 burn: B is told it was burned", async () => {
    s3 = await A.createSecret("To burn", `burn me ${rnd()}`);
    await A.burnNewest();
    await A.waitFor(async () => (await A.sent()).find((x) => x.id === s3.id)?.state === "burned", 5000, "burned");
    await B.openLink(s3.link);
    await B.waitOpenState(s3.id, "burned", 120000);
    await B.screenshot("05-burned");
  });

  await step("6 sender offline at claim time: store catch-up on A", async () => {
    const body = `offline sender ${rnd()}`;
    s4 = await A.createSecret("Sender offline", body);
    await A.stop();
    await B.openLink(s4.link);
    await B.waitOpenState(s4.id, "claiming", 10000);
    await sleep(45000); // let the claim beacons reach the fleet store
    await A.start(); await A.waitDelivery();
    await B.waitOpened(s4.id, body, 240000);
    await B.click("revealClose");
    await A.waitFor(async () => (await A.sent()).find((x) => x.id === s4.id)?.state === "done", 90000, "A shows Opened");
    await A.screenshot("06-after-restart");
  });

  await step("7 both offline in turn: claim and release both recovered from store", async () => {
    const body = `both offline ${rnd()}`;
    s5 = await A.createSecret("Both offline", body);
    await A.stop();
    await B.openLink(s5.link);
    await B.waitOpenState(s5.id, "claiming", 10000);
    await sleep(45000);
    await B.stop();
    await A.start(); await A.waitDelivery();
    await A.waitFor(async () => (await A.sent()).find((x) => x.id === s5.id)?.served === 1, 240000, "A released from the stored claim");
    await A.waitFor(async () => (await A.sent()).find((x) => x.id === s5.id)?.readers[0]?.confirmed === true, 120000, "release confirmed by a store node");
    await B.start(); await B.waitDelivery();
    await B.waitOpened(s5.id, body, 240000);
    await B.screenshot("07-recovered");
    await B.click("revealClose");
    await A.waitFor(async () => (await A.sent()).find((x) => x.id === s5.id)?.state === "done", 90000, "A shows read");
  });

  await step("8 two readers: B and C both read, A counts both", async () => {
    await C.start(); await C.waitDelivery();
    const body = `for two ${rnd()}`;
    await A.setReaders(2);
    const s6 = await A.createSecret("Two readers", body);
    if ((await A.sent()).find((x) => x.id === s6.id).maxReads !== 2) throw new Error("secret not created for 2 readers");
    await B.openLink(s6.link);
    await B.waitOpened(s6.id, body);
    await B.click("revealClose");
    await A.waitFor(async () => { const r = (await A.sent()).find((x) => x.id === s6.id); return r && r.served === 1 && r.state === "open"; }, 30000, "A shows 1 of 2");
    await C.openLink(s6.link);
    await C.waitOpened(s6.id, body);
    await C.click("revealClose");
    await A.waitFor(async () => { const r = (await A.sent()).find((x) => x.id === s6.id); return r && r.served === 2 && r.acked === 2 && r.state === "done"; }, 60000, "A shows read by both");
    const row = (await A.sent()).find((x) => x.id === s6.id);
    if (row.readers.length !== 2 || row.readers[0].fp === row.readers[1].fp) throw new Error("two distinct reader receipts expected");
    log(`A receipts: ${row.label}; devices ${row.readers.map((r) => r.fp).join(", ")}`);
    await A.screenshot("08-two-readers");
  });

  await step("9 single reader: a second person is told it is gone", async () => {
    const body = `only one ${rnd()}`;
    await A.setReaders(1);
    const s7 = await A.createSecret("Only one", body);
    if ((await A.sent()).find((x) => x.id === s7.id).maxReads !== 1) throw new Error("secret not created for 1 reader");
    await B.openLink(s7.link);
    await B.waitOpened(s7.id, body);
    await B.click("revealClose");
    await C.openLink(s7.link);
    await C.waitFor(async () => {
      const r = await C.props("onesecretRoot");
      return r.openId === s7.id && (r.openState === "gone" || r.openState === "opened");
    }, 60000, "C answered");
    const st = await C.rootProp("openState");
    if (st !== "gone") throw new Error(`C state ${st}: a second reader must be refused`);
    log(`C: ${st}: ${await C.rootProp("openInfo")}`);
    await C.screenshot("09-gone");
    await C.stop();
  });
}

main()
  .catch(async (e) => { log(`ABORT: ${e.message}`); await A.screenshot("fail").catch(() => {}); await B.screenshot("fail").catch(() => {}); })
  .finally(async () => {
    if (!KEEP) { for (const p of [A, B, C]) await p.stop().catch((e) => log(`${p.name}: stop: ${e.message}`)); }
    log("RESULTS");
    for (const r of results) log(`  ${r.ok ? "PASS" : "FAIL"}  ${r.name}${r.error ? "  (" + r.error + ")" : ""}`);
    const failed = results.filter((r) => !r.ok).length;
    fs.writeFileSync(path.join(WORK, "results.json"), JSON.stringify(results, null, 2));
    process.exit(failed ? 1 : 0);
  });
