#!/usr/bin/env node
"use strict"

const fs = require("fs")
const path = require("path")
const vm = require("vm")
const assert = require("assert")
const crypto = require("crypto")
const { truePositives, benignClipboard, benignGitDiffs } = require("./corpus")

const ROOT = path.resolve(__dirname, "..")
const JS = path.join(ROOT, "js")
const FIX = path.join(__dirname, "fixtures")

function loadEngine(file) {
  const src = fs
    .readFileSync(path.join(JS, file), "utf8")
    .replace(/^\.pragma library\s*\n/, "")
  const sandbox = {
    console,
    Date,
    Math,
    JSON,
    String,
    Number,
    Array,
    Object,
    parseInt,
    isNaN,
    RegExp,
    exports: {},
    module: { exports: {} }
  }
  vm.createContext(sandbox)
  vm.runInContext(src, sandbox, { filename: file })
  const exported = {}
  for (const key of Object.keys(sandbox)) {
    if (["console", "Date", "Math", "JSON", "String", "Number", "Array", "Object", "parseInt", "isNaN", "RegExp", "exports", "module"].indexOf(key) >= 0)
      continue
    exported[key] = sandbox[key]
  }
  return exported
}

const Detect = loadEngine("Detect.js")
const GitRedact = loadEngine("GitRedact.js")
const Allow = loadEngine("Allow.js")
const Protocol = loadEngine("Protocol.js")
const State = loadEngine("State.js")
const Binds = loadEngine("Binds.js")

let passed = 0
let failed = 0

function test(name, fn) {
  try {
    fn()
    passed += 1
    process.stdout.write("ok  " + name + "\n")
  } catch (err) {
    failed += 1
    process.stderr.write("FAIL " + name + "\n" + (err && err.stack ? err.stack : err) + "\n")
  }
}

function sha256(s) {
  return crypto.createHash("sha256").update(s).digest("hex")
}

function fixture(name) {
  return fs.readFileSync(path.join(FIX, name), "utf8")
}

const rules = Detect.compileRules()

test("canned AWS example is tier-1 aws-access-key", () => {
  const hits = Detect.scan(Protocol.cannedTestSecret(), { rules, src: "clipboard" })
  assert.strictEqual(hits.length, 1)
  assert.strictEqual(hits[0].rule, "aws-access-key")
  assert.strictEqual(hits[0].tier, 1)
  assert.strictEqual(hits[0].redacted_preview, "AKIA…")
})

test("preview is first 4 chars plus ellipsis", () => {
  assert.strictEqual(Detect.previewOf("AKIAIOSFODNN7EXAMPLE"), "AKIA…")
  assert.strictEqual(Detect.previewOf("ghp_abcdefgh"), "ghp_…")
})

test("UUID does not alarm", () => {
  const hits = Detect.scan("550e8400-e29b-41d4-a716-446655440000", { rules, src: "clipboard" })
  assert.strictEqual(hits.length, 0)
})

test("JWT is tier-2 clipboard alert, git log-only", () => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.signaturexx"
  const clip = Detect.scan(jwt, { rules, src: "clipboard" })
  assert.ok(clip.some((h) => h.rule === "jwt" && h.tier === 2 && h.type === "alert"))
  const diff = "diff --git a/t b/t\n--- a/t\n+++ b/t\n@@ -0,0 +1,1 @@\n+" + jwt + "\n"
  const git = Detect.scanAddedLines(diff, { rules })
  assert.ok(git.some((h) => h.rule === "jwt" && h.type === "log"))
  assert.ok(!git.some((h) => h.rule === "jwt" && h.type === "alert"))
})

test("entropy requires nearby keyword", () => {
  const blob = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW"
  assert.ok(Detect.shannon(blob) > 4.2)
  assert.ok(!Detect.scan(blob, { rules }).some((h) => h.rule === "entropy"))
  assert.ok(Detect.scan("password=" + blob, { rules }).some((h) => h.rule === "entropy" && h.tier === 2))
})

test("NUL and empty skipped", () => {
  assert.strictEqual(Detect.scan("", { rules }).length, 0)
  assert.strictEqual(Detect.scan("AKI\0AIOSFODNN7EXAMPLE", { rules }).length, 0)
})

test("true-positives.json fixtures fire at the right rule/tier", () => {
  const list = JSON.parse(fixture("true-positives.json"))
  for (const row of list) {
    const hits = Detect.scan(row.text, { rules, src: "clipboard" })
    const hit = hits.find((h) => h.rule === row.rule)
    assert.ok(hit, row.id + " missing " + row.rule + " in " + JSON.stringify(hits.map((h) => h.rule)))
    assert.strictEqual(hit.tier, row.tier, row.id)
  }
})

test("60 generated true positives fire at the declared tier", () => {
  const list = truePositives()
  assert.ok(list.length >= 60, "need 60, got " + list.length)
  for (const row of list) {
    const hits = Detect.scan(row.text, { rules, src: "clipboard" })
    const hit = hits.find((h) => h.rule === row.rule && h.tier === row.tier)
    assert.ok(hit, row.id + " expected " + row.rule + " t" + row.tier + " got " + JSON.stringify(hits))
  }
})

test("500 benign clipboard samples produce zero tier-1", () => {
  const samples = benignClipboard(500)
  assert.strictEqual(samples.length, 500)
  for (let i = 0; i < samples.length; i++) {
    const hits = Detect.scan(samples[i], { rules, src: "clipboard" })
    const t1 = hits.filter((h) => h.tier === 1)
    assert.strictEqual(t1.length, 0, "clipboard[" + i + "] " + samples[i] + " -> " + JSON.stringify(t1))
  }
})

test("500 benign staged-diff samples produce zero tier-1", () => {
  const samples = benignGitDiffs(500)
  assert.strictEqual(samples.length, 500)
  for (let i = 0; i < samples.length; i++) {
    const hits = Detect.scanAddedLines(samples[i], { rules })
    const t1 = hits.filter((h) => h.tier === 1)
    assert.strictEqual(t1.length, 0, "git[" + i + "] -> " + JSON.stringify(t1))
  }
})

test("public events never leak 8+ char secret substrings", () => {
  const list = truePositives().filter((r) => r.tier === 1)
  for (const row of list) {
    const hits = Detect.scan(row.text, { rules, src: "clipboard" })
    for (const hit of hits) {
      const pub = Detect.publicEvent(hit)
      assert.ok(!Detect.eventLeaksSecret(pub, hit.value), row.id + " leaked via " + JSON.stringify(pub))
    }
  }
})

test("quoted diff --git paths keep spaces", () => {
  const diff = "diff --git \"a/my secrets/.env\" \"b/my secrets/.env\"\nindex 1..2 100644\n--- \"a/my secrets/.env\"\n+++ \"b/my secrets/.env\"\n@@ -1,0 +2,1 @@\n+AKIAIOSFODNN7EXAMPLE\n"
  const plan = GitRedact.plan(diff, Detect.scan, { rules, src: "git" })
  assert.strictEqual(plan.files[0], "my secrets/.env")
})

test("reinjection check uses full-offer hash", () => {
  const sup = Allow.suppression()
  const offer = "note\nAKIAIOSFODNN7EXAMPLE\n"
  const offerH = sha256(offer)
  const secretH = sha256("AKIAIOSFODNN7EXAMPLE")
  Allow.rememberRedact(sup, secretH, 10)
  Allow.rememberRedact(sup, offerH, 10)
  assert.ok(Allow.restoredByManager(sup, offerH, 11))
  assert.ok(!Allow.permanentlySuppressed(sup, offerH))
})

test("git redact keeps only the secret added line", () => {
  const diff = fixture("git-diff-mixed.patch")
  const plan = GitRedact.plan(diff, Detect.scan, { rules, src: "git" })
  assert.ok(plan.patch.indexOf("AKIAIOSFODNN7EXAMPLE") >= 0)
  assert.ok(plan.patch.indexOf("UNRELATED_SETTING") < 0)
  assert.strictEqual(plan.files[0], ".env")
  assert.strictEqual(GitRedact.fallbackLabel(), "file unstaged (all hunks)")
})

test("clean git diff plans nothing", () => {
  const plan = GitRedact.plan(fixture("git-diff-clean.patch"), Detect.scan, { rules, src: "git" })
  assert.strictEqual(plan.mode, "none")
  assert.strictEqual(plan.patch, "")
})

test("replacement hunk uses labeled whole-file fallback", () => {
  const plan = GitRedact.plan(fixture("git-diff-replace.patch"), Detect.scan, { rules, src: "git" })
  assert.strictEqual(plan.patch, "")
  assert.ok(plan.fallbackFiles.indexOf(".env") >= 0)
  assert.strictEqual(plan.mode, "unstaged-all")
  assert.strictEqual(plan.label, "file unstaged (all hunks)")
})

test("allowlist stores hashes not plaintext", () => {
  const store = Allow.empty()
  const secret = Protocol.cannedTestSecret()
  const hex = Allow.sha256Hex(secret, sha256)
  Allow.addValue(store, hex)
  const dumped = Allow.serialize(store)
  assert.ok(dumped.indexOf(secret) < 0)
  assert.ok(dumped.indexOf("AKIA") < 0)
  assert.ok(Allow.isAllowedHash(store, hex))
})

test("redaction marker is permanent; secret hash is only recent", () => {
  const sup = Allow.suppression()
  const marker = sha256(Allow.redactString())
  const secret = sha256(Protocol.cannedTestSecret())
  Allow.suppressMarker(sup, marker)
  Allow.rememberRedact(sup, secret, 1)
  assert.ok(Allow.permanentlySuppressed(sup, marker))
  assert.ok(!Allow.permanentlySuppressed(sup, secret))
  assert.ok(Allow.restoredByManager(sup, secret, 1 + 1000))
  assert.ok(!Allow.restoredByManager(sup, secret, 1 + Allow.restoreWindowMs() + 1))
})

test("protocol summon rules", () => {
  const t1 = Protocol.alertEvent({ rule: "aws-access-key", tier: 1, src: "clipboard" })
  const t2 = Protocol.alertEvent({ rule: "jwt", tier: 2, src: "clipboard" })
  assert.ok(Protocol.shouldSummonOverlay(t1, false))
  assert.ok(!Protocol.shouldSummonOverlay(t2, false))
  assert.ok(!Protocol.shouldSummonOverlay(t1, true))
  assert.ok(Protocol.shouldAmberBar(t2))
})

test("shared state bar levels", () => {
  State.applyStatus({ watching: true, degraded: false, clipboard: "watch" })
  State.clearIncident()
  assert.strictEqual(State.snapshot().barLevel, "green")
  State.applyAlert({ type: "alert", src: "clipboard", rule: "jwt", title: "JWT in clipboard", tier: 2, redacted_preview: "eyJh…" })
  assert.strictEqual(State.snapshot().barLevel, "amber")
  State.applyAlert({ type: "alert", src: "clipboard", rule: "aws-access-key", title: "AWS key in clipboard", tier: 1, redacted_preview: "AKIA…" })
  assert.strictEqual(State.snapshot().barLevel, "red")
})

test("1 MB cap does not throw", () => {
  const huge = "x".repeat(2 * 1024 * 1024)
  const hits = Detect.scan(huge, { rules })
  assert.ok(Array.isArray(hits))
})

test("fallback IPC verbs map to registered methods", () => {
  assert.strictEqual(Protocol.ipcVerb("testCanary"), "test")
  assert.strictEqual(Protocol.ipcVerb("watchRepo"), "watch")
  assert.strictEqual(Protocol.ipcVerb("unwatchRepo"), "unwatch")
  assert.strictEqual(Protocol.ipcVerb("redactGit"), "redactGit")
  assert.strictEqual(Protocol.ipcVerb("allowlist"), "allowlist")
})

test("git redact scope is incident file only", () => {
  const diff = [
    "diff --git a/.env b/.env",
    "--- a/.env",
    "+++ b/.env",
    "@@ -0,0 +1,1 @@",
    "+AKIAIOSFODNN7EXAMPLE",
    "diff --git a/other.env b/other.env",
    "--- a/other.env",
    "+++ b/other.env",
    "@@ -0,0 +1,1 @@",
    "+AKIAIOSFODNN7EXAMPLE",
    "diff --git a/blob.bin b/blob.bin",
    "Binary files a/blob.bin and b/blob.bin differ",
    ""
  ].join("\n")
  const pred = (line) => line.indexOf("AKIAIOSFODNN7EXAMPLE") >= 0
  const scoped = GitRedact.filterPatch(diff, pred, ".env")
  assert.ok(scoped.patch.indexOf("AKIAIOSFODNN7EXAMPLE") >= 0)
  assert.ok(scoped.patch.indexOf("other.env") < 0)
  assert.strictEqual(scoped.fallbackFiles.indexOf("blob.bin"), -1)
  assert.strictEqual(scoped.files.length, 1)
  assert.strictEqual(scoped.files[0].path, ".env")
  const open = GitRedact.filterPatch(diff, pred)
  assert.strictEqual(open.fallbackFiles.indexOf("blob.bin"), -1)
})

test("command includes incident hash for remediation", () => {
  const line = Protocol.command("redact-git", { hash: "deadbeef" })
  const obj = JSON.parse(line)
  assert.strictEqual(obj.cmd, "redact-git")
  assert.strictEqual(obj.hash, "deadbeef")
  const ev = Protocol.alertEvent({ rule: "aws-access-key", hash: "abc", tier: 1, src: "git" })
  assert.strictEqual(ev.hash, "abc")
})

test("demo AWS pair yields two distinct hashes; first is the actionable one", () => {
  const text =
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nKEEP_ME=1\n"
  const hits = Detect.scan(text, { rules, src: "git" }).filter((h) => h.tier === 1 && h.type === "alert")
  assert.ok(hits.some((h) => h.rule === "aws-access-key"))
  assert.ok(hits.some((h) => h.rule === "aws-secret-access-key"))
  const first = hits[0]
  const last = hits[hits.length - 1]
  assert.notStrictEqual(first.rule, last.rule)
  const firstHash = sha256(first.value)
  const lastHash = sha256(last.value)
  assert.notStrictEqual(firstHash, lastHash)
  const cmd = JSON.parse(Protocol.command("redact-git", { hash: firstHash }))
  assert.strictEqual(cmd.hash, firstHash)
  assert.notStrictEqual(cmd.hash, lastHash)
  State.clearIncident()
  State.applyAlert(Protocol.alertEvent({ ...first, hash: firstHash }))
  assert.strictEqual(State.snapshot().lastIncident.hash, firstHash)
  State.applyAlert(Protocol.alertEvent({ ...last, hash: lastHash }))
  assert.strictEqual(State.snapshot().lastIncident.hash, lastHash, "last write still overwrites; daemon must emit only one")
})

test("redactCommand dispatches on src, never both", () => {
  assert.strictEqual(Protocol.redactCommand("clipboard"), "redact-clip")
  assert.strictEqual(Protocol.redactCommand("git"), "redact-git")
  assert.strictEqual(Protocol.redactCommand(""), "redact-clip")
  assert.notStrictEqual(Protocol.redactCommand("clipboard"), Protocol.redactCommand("git"))
})

test("restore is clipboard-only", () => {
  assert.ok(Protocol.canRestore("clipboard"))
  assert.ok(!Protocol.canRestore("git"))
  assert.ok(!Protocol.canRestore(""))
})

test("rule catalog covers tier-1 ids and jwt/entropy", () => {
  const ids = Protocol.ruleCatalog().map((r) => r.id)
  assert.ok(ids.indexOf("aws-access-key") >= 0)
  assert.ok(ids.indexOf("jwt") >= 0)
  assert.ok(ids.indexOf("entropy") >= 0)
  assert.ok(Protocol.ruleCatalog().length >= 12)
})

test("binds: empty live list offers redact and summon preferreds", () => {
  const p = Binds.plan([])
  assert.strictEqual(p.needed, true)
  assert.strictEqual(p.toAdd.length, 2)
  assert.strictEqual(p.toAdd[0].chosen, "SUPER + ALT + X")
  assert.strictEqual(p.toAdd[1].chosen, "SUPER + ALT + SHIFT + C")
  const lua = Binds.luaBlock(p.toAdd)
  assert.ok(lua.indexOf("o.bind(\"SUPER + ALT + X\"") === 0)
  assert.ok(lua.indexOf("redact") >= 0)
  assert.ok(p.toAdd.every((x) => x.chosen !== "SUPER + CTRL + X"))
  assert.ok(p.toAdd.every((x) => x.chosen !== "SUPER + CTRL + C"))
})

test("binds: stock dictation and capture do not steal preferreds", () => {
  const live = [
    { modmask: 68, key: "X", dispatcher: "__lua", arg: "268", description: "Toggle dictation" },
    { modmask: 68, key: "C", dispatcher: "__lua", arg: "35", description: "Capture menu" }
  ]
  const p = Binds.plan(live)
  assert.strictEqual(p.needed, true)
  assert.strictEqual(p.toAdd[0].chosen, "SUPER + ALT + X")
  assert.strictEqual(p.toAdd[1].chosen, "SUPER + ALT + SHIFT + C")
})

test("binds: chroma SUPER+ALT+C does not steal summon preferred", () => {
  const live = [
    { modmask: 72, key: "C", dispatcher: "__lua", arg: "omarchy-shell shell summon io.github.chris.chroma '{}'", description: "Chroma" }
  ]
  const p = Binds.plan(live)
  assert.strictEqual(p.needed, true)
  const summon = p.toAdd.filter((x) => x.desc === "Secret Canary")[0]
  assert.ok(summon)
  assert.strictEqual(summon.chosen, "SUPER + ALT + SHIFT + C")
})

test("binds: summon preferred taken falls back to SUPER+ALT+C if free", () => {
  const live = [
    { modmask: 73, key: "C", dispatcher: "exec", arg: "other", description: "taken" }
  ]
  const p = Binds.plan(live)
  const summon = p.toAdd.filter((x) => x.desc === "Secret Canary")[0]
  assert.strictEqual(summon.chosen, "SUPER + ALT + C")
})

test("binds: chroma live SUPER+ALT+C skips summon if preferred is also taken", () => {
  const live = [
    { modmask: 73, key: "C", dispatcher: "exec", arg: "other", description: "taken" },
    { modmask: 72, key: "C", dispatcher: "__lua", arg: "15", description: "Chroma" }
  ]
  const p = Binds.plan(live)
  const summon = p.toAdd.filter((x) => x.desc === "Secret Canary")[0]
  assert.ok(!summon)
  const skipped = p.skipped.filter((x) => x.desc === "Secret Canary")[0]
  assert.ok(skipped)
})

test("binds: already-ours via lua description hides the offer", () => {
  const live = [
    { modmask: 72, key: "X", dispatcher: "__lua", arg: "15", description: "Secret Canary redact" }
  ]
  const p = Binds.plan(live)
  assert.strictEqual(p.needed, false)
  assert.ok(p.already >= 1)
  assert.strictEqual(p.toAdd.length, 0)
})

test("binds: notify body lists assigned keys", () => {
  const body = Binds.notifyBody([{ chosen: "SUPER + ALT + X", desc: "Secret Canary redact" }], [])
  assert.ok(body.indexOf("SUPER + ALT + X — Secret Canary redact") === 0)
  const argv = Binds.notifyArgv("Secret Canary", "Secret Canary keybindings", body)
  assert.strictEqual(argv[0], "omarchy")
  assert.strictEqual(argv[1], "notification")
  assert.strictEqual(argv[2], "send")
  assert.strictEqual(argv[4], "Secret Canary")
  assert.strictEqual(argv[7], "Secret Canary keybindings")
})

test("binds: claimAuto is one-shot", () => {
  assert.strictEqual(Binds.claimAuto(), true)
  assert.strictEqual(Binds.claimAuto(), false)
})

test("qml: no Add keybindings button or keys chip", () => {
  for (const rel of ["Overlay.qml", "BarWidget.qml", "Service.qml"]) {
    const src = fs.readFileSync(path.join(ROOT, rel), "utf8")
    assert.ok(src.indexOf("Add keybindings") < 0, rel)
    assert.ok(src.indexOf('text: "keys"') < 0, rel)
  }
  const service = fs.readFileSync(path.join(ROOT, "Service.qml"), "utf8")
  assert.ok(service.indexOf("Binds.claimAuto()") >= 0)
})

console.log(passed + " passed, " + failed + " failed")
process.exit(failed ? 1 : 0)
