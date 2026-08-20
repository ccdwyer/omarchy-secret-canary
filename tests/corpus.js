"use strict"

const crypto = require("crypto")

function awsKey(i) {
  const body = ("000000000000000" + i.toString(36).toUpperCase()).slice(-16)
  return "AKIA" + body.replace(/[^0-9A-Z]/g, "A")
}

function ghp(i) {
  return "ghp_" + crypto.createHash("sha256").update("ghp" + i).digest("hex").slice(0, 36)
}

function jwt(i) {
  const h = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString("base64url")
  const p = Buffer.from('{"sub":"' + i + '","name":"x"}').toString("base64url")
  const s = crypto.createHash("sha256").update("jwt" + i).digest("base64url").slice(0, 20)
  return h + "." + p + "." + s
}

function entropySecret(i) {
  const token = crypto.createHash("sha256").update("ent" + i).digest("base64").replace(/[^A-Za-z0-9]/g, "x").slice(0, 32)
  return "api_key=" + token
}

function truePositives() {
  const out = []
  for (let i = 0; i < 10; i++)
    out.push({ id: "aws-" + i, text: awsKey(i), rule: "aws-access-key", tier: 1 })
  out.push({
    id: "aws-secret",
    text: "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    rule: "aws-secret-access-key",
    tier: 1
  })
  for (let i = 0; i < 6; i++)
    out.push({ id: "ghp-" + i, text: ghp(i), rule: "github-pat", tier: 1 })
  out.push({ id: "gho-0", text: "gho_" + "a".repeat(24), rule: "github-oauth", tier: 1 })
  out.push({ id: "ghs-0", text: "ghs_" + "b".repeat(24), rule: "github-app", tier: 1 })
  out.push({ id: "gf-0", text: "github_pat_" + "c".repeat(24), rule: "github-fine-grained", tier: 1 })
  ;["RSA", "EC", "OPENSSH", "PGP"].forEach((k) => {
    out.push({ id: "pem-" + k, text: "-----BEGIN " + k + " PRIVATE KEY-----", rule: "private-key", tier: 1 })
  })
  out.push({ id: "pkcs8", text: "-----BEGIN PRIVATE KEY-----", rule: "private-key-pkcs8", tier: 1 })
  for (let i = 0; i < 8; i++)
    out.push({ id: "sk-" + i, text: "sk-" + "abcdefghijklmnopqrstuvwxyz0123456789".slice(0, 20) + i, rule: "openai-key", tier: 1 })
  out.push({ id: "sk-proj", text: "sk-proj-" + "d".repeat(24), rule: "openai-proj-key", tier: 1 })
  for (let i = 0; i < 8; i++)
    out.push({ id: "slack-" + i, text: "xoxb-EXAMPLENOTAREAL00000" + i, rule: "slack-token", tier: 1 })
  for (let i = 0; i < 8; i++)
    out.push({ id: "jwt-" + i, text: jwt(i), rule: "jwt", tier: 2 })
  for (let i = 0; i < 10; i++)
    out.push({ id: "ent-" + i, text: entropySecret(i), rule: "entropy", tier: 2 })
  return out
}

function uuid(i) {
  const h = crypto.createHash("md5").update("uuid" + i).digest("hex")
  return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20, 32)
}

function benignClipboard(n) {
  const out = []
  const sentences = [
    "The quick brown fox jumps over the lazy dog.",
    "git commit -m 'wip'",
    "https://example.com/path?q=1",
    "rgb(204, 68, 68)",
    "cargo test --release",
    "fn main() { println!(\"hi\"); }",
    "{\"ok\":true,\"count\":12}",
    "/home/chris/projects/demo/src/lib.rs",
    "version 1.2.3-beta.4",
    "SELECT * FROM users WHERE id = 4;"
  ]
  for (let i = 0; i < n; i++) {
    const k = i % 10
    if (k === 0) out.push(uuid(i))
    else if (k === 1) out.push(crypto.createHash("sha1").update("g" + i).digest("hex"))
    else if (k === 2) out.push(sentences[i % sentences.length])
    else if (k === 3) out.push("#" + crypto.createHash("md5").update("c" + i).digest("hex").slice(0, 6))
    else if (k === 4) out.push(String(1600000000 + i))
    else if (k === 5) out.push("package@" + (i % 99) + ".0.0")
    else if (k === 6) out.push("TODO: fix the widget layout " + i)
    else if (k === 7) out.push("-----BEGIN CERTIFICATE-----")
    else if (k === 8) out.push("skater-board-" + i)
    else out.push("AKIA is a prefix but this is not a key")
  }
  return out
}

function benignGitDiffs(n) {
  const out = []
  for (let i = 0; i < n; i++) {
    const kind = i % 8
    let added
    if (kind === 0)
      added = "\"integrity\": \"sha512-" + crypto.createHash("sha256").update("int" + i).digest("base64") + "\""
    else if (kind === 1)
      added = "function x(){return " + i + "}function y(){return x()+1}"
    else if (kind === 2)
      added = "checksum = \"" + crypto.createHash("sha256").update("cs" + i).digest("hex") + "\""
    else if (kind === 3)
      added = "pub fn f_" + i + "() { let _ = " + i + "; }"
    else if (kind === 4)
      added = "resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz\""
    else if (kind === 5)
      added = "github.com/foo/bar v1.2." + (i % 9) + " h1:" + crypto.createHash("sha1").update("go" + i).digest("base64")
    else if (kind === 6)
      added = "<svg viewBox='0 0 10 10'><rect width='10' height='10'/></svg>"
    else
      added = "console.log('hello " + i + "')"
    out.push(
      "diff --git a/f b/f\nindex 1..2 100644\n--- a/f\n+++ b/f\n@@ -1,0 +2,1 @@\n+" + added + "\n"
    )
  }
  return out
}

module.exports = { truePositives, benignClipboard, benignGitDiffs, awsKey }
