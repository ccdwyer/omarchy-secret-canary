.pragma library

// Line-oriented JSON protocol between canaryd and Service.qml.

function parseLine(line) {
    var s = String(line || "").trim()
    if (!s)
        return null
    try {
        return JSON.parse(s)
    } catch (e) {
        return null
    }
}

function command(cmd, fields) {
    var out = { cmd: String(cmd) }
    if (fields && typeof fields === "object") {
        for (var k in fields) {
            if (fields.hasOwnProperty(k))
                out[k] = fields[k]
        }
    }
    return JSON.stringify(out)
}

function alertEvent(partial) {
    var ev = {
        type: "alert",
        src: partial.src || "clipboard",
        rule: partial.rule || "unknown",
        title: partial.title || "",
        tier: Number(partial.tier) || 1,
        redacted_preview: partial.redacted_preview || "",
        actions: partial.actions || [],
        file: partial.file || null,
        repo: partial.repo || null,
        hash: partial.hash || ""
    }
    if (partial.note)
        ev.note = partial.note
    return ev
}

function statusEvent(partial) {
    return {
        type: "status",
        watching: !!partial.watching,
        clipboard: partial.clipboard || "unknown",
        git: partial.git || "idle",
        repos: Number(partial.repos) || 0,
        muted: !!partial.muted,
        degraded: !!partial.degraded,
        helper: partial.helper || "unknown",
        note: partial.note || ""
    }
}

function isAlert(ev) {
    return ev && ev.type === "alert"
}

function isLog(ev) {
    return ev && ev.type === "log"
}

function shouldSummonOverlay(ev, muted) {
    if (muted)
        return false
    if (!isAlert(ev))
        return false
    return Number(ev.tier) === 1
}

function shouldAmberBar(ev) {
    if (!ev)
        return false
    if (ev.type === "status" && ev.degraded)
        return true
    if (isAlert(ev) && Number(ev.tier) > 1 && ev.src !== "git")
        return true
    if (isAlert(ev) && Number(ev.tier) === 1)
        return false
    return false
}

function cannedTestSecret() {
    return "AKIAIOSFODNN7EXAMPLE"
}

function redactCommand(src) {
    return src === "git" ? "redact-git" : "redact-clip"
}

function canRestore(src) {
    return src === "clipboard"
}

function ipcVerb(method) {
    if (method === "testCanary")
        return "test"
    if (method === "watchRepo")
        return "watch"
    if (method === "unwatchRepo")
        return "unwatch"
    return String(method || "")
}

function ruleCatalog() {
    return [
        { id: "aws-access-key", title: "AWS key", tier: 1 },
        { id: "aws-secret-access-key", title: "AWS secret key", tier: 1 },
        { id: "github-pat", title: "GitHub PAT", tier: 1 },
        { id: "github-oauth", title: "GitHub OAuth", tier: 1 },
        { id: "github-app", title: "GitHub App token", tier: 1 },
        { id: "github-fine-grained", title: "GitHub fine-grained", tier: 1 },
        { id: "private-key", title: "Private key (PEM)", tier: 1 },
        { id: "private-key-pkcs8", title: "Private key (PKCS8)", tier: 1 },
        { id: "openai-key", title: "API key (sk-)", tier: 1 },
        { id: "openai-proj-key", title: "API key (sk-proj)", tier: 1 },
        { id: "slack-token", title: "Slack token", tier: 1 },
        { id: "jwt", title: "JWT", tier: 2 },
        { id: "entropy", title: "High-entropy + context", tier: 2 }
    ]
}
