.pragma library

// Secret Canary detection engine. Mirrors src/canaryd/src/detect.rs.
// Keep the two implementations in lockstep: same ids, same regexes, same
// Shannon threshold, same preview truncation.

var MAX_BYTES = 1048576
var ENTROPY_THRESHOLD = 4.2
var ENTROPY_MIN_LEN = 24
var CONTEXT_RADIUS = 40
var PREVIEW_CHARS = 4
var CONTEXT_RE = /secret|token|password|api[_-]?key/i
var TOKEN_RE = /[A-Za-z0-9/_+=.-]{24,}/g

var DEFAULT_RULES = [
    { id: "aws-access-key", tier: 1, title: "AWS key", regex: "AKIA[0-9A-Z]{16}" },
    { id: "aws-secret-access-key", tier: 1, title: "AWS secret key", regex: "(?:aws)?_?secret_?(?:access)?_?key[\"'\\s:=]{0,16}([A-Za-z0-9/+=]{40})", flags: "i" },
    { id: "github-pat", tier: 1, title: "GitHub token", regex: "ghp_[A-Za-z0-9]{20,}" },
    { id: "github-oauth", tier: 1, title: "GitHub token", regex: "gho_[A-Za-z0-9]{20,}" },
    { id: "github-app", tier: 1, title: "GitHub token", regex: "ghs_[A-Za-z0-9]{20,}" },
    { id: "github-fine-grained", tier: 1, title: "GitHub token", regex: "github_pat_[A-Za-z0-9_]{20,}" },
    { id: "private-key", tier: 1, title: "Private key", regex: "-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----" },
    { id: "private-key-pkcs8", tier: 1, title: "Private key", regex: "-----BEGIN PRIVATE KEY-----" },
    { id: "openai-key", tier: 1, title: "API key", regex: "sk-[A-Za-z0-9]{20,}" },
    { id: "openai-proj-key", tier: 1, title: "API key", regex: "sk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}" },
    { id: "slack-token", tier: 1, title: "Slack token", regex: "xox[baprs]-[A-Za-z0-9-]{10,}" },
    { id: "jwt", tier: 2, title: "JWT", regex: "eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}" }
]

function compileRules(list) {
    var src = list && list.length ? list : DEFAULT_RULES
    var out = []
    for (var i = 0; i < src.length; i++) {
        var r = src[i]
        var flags = r.flags || ""
        out.push({
            id: r.id,
            tier: Number(r.tier) || 1,
            title: r.title || r.id,
            re: new RegExp(r.regex, flags + (flags.indexOf("g") >= 0 ? "" : "g"))
        })
    }
    return out
}

function capText(text) {
    var s = text === undefined || text === null ? "" : String(text)
    if (s.length <= MAX_BYTES)
        return s
    // JS strings are UTF-16; slice on code units is a char-safe cap for BMP.
    return s.slice(0, MAX_BYTES)
}

function containsNul(text) {
    return String(text).indexOf("\0") >= 0
}

function shannon(s) {
    if (!s || !s.length)
        return 0
    var freq = {}
    for (var i = 0; i < s.length; i++) {
        var c = s.charAt(i)
        freq[c] = (freq[c] || 0) + 1
    }
    var h = 0
    var n = s.length
    for (var k in freq) {
        if (!freq.hasOwnProperty(k))
            continue
        var p = freq[k] / n
        h -= p * (Math.log(p) / Math.log(2))
    }
    return h
}

function previewOf(value) {
    var s = String(value || "")
    if (!s.length)
        return ""
    var head = s.slice(0, PREVIEW_CHARS)
    return head + "…"
}

function humanTitle(rule, src, file) {
    var title = (rule && rule.title) ? rule.title : "Secret"
    var where = src === "git" ? "staged" : "in clipboard"
    if (src === "git" && file)
        return title + " " + where + " in " + file
    if (src === "git")
        return title + " " + where
    return title + " " + where
}

function actionsFor(src) {
    if (src === "git")
        return ["redact-git"]
    return ["redact-clip"]
}

function resetRegex(re) {
    re.lastIndex = 0
}

function firstCapture(match) {
    if (!match)
        return ""
    if (match.length > 1 && match[1])
        return match[1]
    return match[0]
}

function contextAround(text, index, length) {
    var start = Math.max(0, index - CONTEXT_RADIUS)
    var end = Math.min(text.length, index + length + CONTEXT_RADIUS)
    return text.slice(start, end)
}

function findEntropyHits(text, already) {
    var hits = []
    TOKEN_RE.lastIndex = 0
    var m
    while ((m = TOKEN_RE.exec(text)) !== null) {
        var token = m[0]
        if (token.length < ENTROPY_MIN_LEN)
            continue
        if (already[token])
            continue
        if (shannon(token) <= ENTROPY_THRESHOLD)
            continue
        var ctx = contextAround(text, m.index, token.length)
        if (!CONTEXT_RE.test(ctx))
            continue
        CONTEXT_RE.lastIndex = 0
        hits.push({
            id: "entropy",
            title: "High-entropy secret",
            tier: 2,
            value: token,
            index: m.index
        })
        already[token] = true
    }
    return hits
}

function scan(text, opts) {
    opts = opts || {}
    var src = opts.src || "clipboard"
    var file = opts.file || null
    var repo = opts.repo || null
    var disabled = opts.disabledRules || {}
    var allow = opts.allowValues || {}
    var rules = opts.rules || compileRules()

    if (text === undefined || text === null)
        return []
    if (containsNul(text))
        return []
    var body = capText(text)
    if (!body.length)
        return []

    var seenValues = {}
    var raw = []

    for (var i = 0; i < rules.length; i++) {
        var rule = rules[i]
        if (disabled[rule.id])
            continue
        resetRegex(rule.re)
        var match
        while ((match = rule.re.exec(body)) !== null) {
            var value = firstCapture(match)
            if (!value)
                continue
            if (allow[value])
                continue
            if (seenValues[rule.id + "\0" + value])
                continue
            seenValues[rule.id + "\0" + value] = true
            raw.push({
                id: rule.id,
                title: rule.title,
                tier: rule.tier,
                value: value,
                index: match.index
            })
            if (rule.re.lastIndex === match.index)
                rule.re.lastIndex += 1
        }
    }

    var covered = {}
    for (var j = 0; j < raw.length; j++)
        covered[raw[j].value] = true

    if (!disabled.entropy) {
        var extra = findEntropyHits(body, covered)
        for (var e = 0; e < extra.length; e++) {
            if (allow[extra[e].value])
                continue
            raw.push(extra[e])
        }
    }

    raw.sort(function (a, b) {
        if (a.tier !== b.tier)
            return a.tier - b.tier
        return a.index - b.index
    })

    var events = []
    for (var k = 0; k < raw.length; k++) {
        var hit = raw[k]
        var gitLogOnly = src === "git" && hit.tier > 1
        events.push({
            type: gitLogOnly ? "log" : "alert",
            src: src,
            rule: hit.id,
            title: humanTitle(hit, src, file),
            tier: hit.tier,
            redacted_preview: previewOf(hit.value),
            actions: gitLogOnly ? [] : actionsFor(src),
            file: file,
            repo: repo,
            value: hit.value
        })
    }
    return events
}

function scanAddedLines(diffText, opts) {
    opts = opts || {}
    var added = extractAddedLines(diffText)
    if (!added.text)
        return []
    var events = scan(added.text, {
        src: "git",
        file: opts.file || added.firstFile,
        repo: opts.repo || null,
        disabledRules: opts.disabledRules,
        allowValues: opts.allowValues,
        rules: opts.rules
    })
    for (var i = 0; i < events.length; i++) {
        if (!events[i].file)
            events[i].file = added.fileForValue(events[i].value) || added.firstFile
    }
    return events
}

function extractAddedLines(diffText) {
    var text = String(diffText || "")
    var lines = text.split("\n")
    var chunks = []
    var files = []
    var current = null
    var map = []
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i]
        if (line.indexOf("diff --git ") === 0) {
            var parts = line.split(" ")
            var b = parts.length ? parts[parts.length - 1] : ""
            if (b.indexOf("b/") === 0)
                b = b.slice(2)
            current = b
            files.push(b)
            continue
        }
        if (line.indexOf("+++ ") === 0)
            continue
        if (line.charAt(0) === "+" && line.indexOf("+++") !== 0) {
            var added = line.slice(1)
            chunks.push(added)
            map.push(current)
        }
    }
    return {
        text: chunks.join("\n"),
        firstFile: files.length ? files[0] : null,
        fileForValue: function (value) {
            for (var j = 0; j < chunks.length; j++) {
                if (chunks[j].indexOf(value) >= 0)
                    return map[j]
            }
            return files.length ? files[0] : null
        }
    }
}

function publicEvent(ev) {
    if (!ev)
        return null
    return {
        type: ev.type,
        src: ev.src,
        rule: ev.rule,
        title: ev.title,
        tier: ev.tier,
        redacted_preview: ev.redacted_preview,
        actions: ev.actions || [],
        file: ev.file || null,
        repo: ev.repo || null
    }
}

function eventLeaksSecret(ev, secret) {
    if (!ev || !secret || secret.length < 8)
        return false
    var copy = publicEvent(ev)
    var dumped = JSON.stringify(copy)
    var i
    for (i = 0; i <= secret.length - 8; i++) {
        var slice = secret.slice(i, i + 8)
        if (dumped.indexOf(slice) >= 0)
            return true
    }
    return false
}
