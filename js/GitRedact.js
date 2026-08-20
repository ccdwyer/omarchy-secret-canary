.pragma library

// Surgical staged-diff redaction. Mirrors src/canaryd/src/git.rs.
// Primary path: keep only hunks whose added lines match a secret, then
// `git apply --cached -R` that patch. Fallback: whole-file unstage,
// labelled "file unstaged (all hunks)". Never touches the worktree.

function parseDiff(text) {
    var raw = String(text || "")
    if (!raw.length)
        return []
    var files = []
    var current = null
    var hunk = null
    var lines = raw.replace(/\r\n/g, "\n").split("\n")
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i]
        if (line.indexOf("diff --git ") === 0) {
            if (current)
                files.push(current)
            current = {
                header: [line],
                path: pathFromDiffGit(line),
                binary: false,
                hunks: []
            }
            hunk = null
            continue
        }
        if (!current)
            continue
        if (line.indexOf("Binary files ") === 0 || line.indexOf("GIT binary patch") === 0) {
            current.binary = true
            current.header.push(line)
            hunk = null
            continue
        }
        if (line.indexOf("@@ ") === 0) {
            hunk = { header: line, lines: [] }
            current.hunks.push(hunk)
            continue
        }
        if (hunk)
            hunk.lines.push(line)
        else
            current.header.push(line)
    }
    if (current)
        files.push(current)
    return files
}

function stripAb(p) {
    var s = String(p || "")
    if (s.indexOf("a/") === 0 || s.indexOf("b/") === 0)
        return s.slice(2)
    return s
}

function unquoteC(s) {
    var out = ""
    for (var i = 0; i < s.length; i++) {
        var c = s.charAt(i)
        if (c === "\"")
            return { text: out, rest: s.slice(i + 1) }
        if (c === "\\" && i + 1 < s.length) {
            i += 1
            var n = s.charAt(i)
            if (n === "n") out += "\n"
            else if (n === "t") out += "\t"
            else if (n === "r") out += "\r"
            else out += n
            continue
        }
        out += c
    }
    return { text: out, rest: "" }
}

function nextDiffPath(s) {
    s = String(s || "").replace(/^\s+/, "")
    if (!s)
        return null
    if (s.charAt(0) === "\"") {
        var q = unquoteC(s.slice(1))
        return { path: stripAb(q.text), rest: q.rest }
    }
    var idx = -1
    for (var i = 0; i < s.length; i++) {
        if (s.charAt(i) !== " ")
            continue
        var rest = s.slice(i + 1)
        if (rest.indexOf("a/") === 0 || rest.indexOf("b/") === 0 || rest.charAt(0) === "\"") {
            idx = i
            break
        }
    }
    if (idx >= 0)
        return { path: stripAb(s.slice(0, idx)), rest: s.slice(idx + 1) }
    return { path: stripAb(s), rest: "" }
}

function pathFromDiffGit(line) {
    var rest = String(line || "")
    var marker = "diff --git "
    if (rest.indexOf(marker) === 0)
        rest = rest.slice(marker.length)
    var first = nextDiffPath(rest)
    if (!first)
        return ""
    var second = nextDiffPath(first.rest)
    return second ? second.path : first.path
}

function parseHunkHeader(header) {
    var plus = String(header).indexOf("+")
    if (plus < 0)
        return { start: 1, count: 0 }
    var rest = String(header).slice(plus + 1)
    var end = rest.search(/[\s@]/)
    if (end < 0)
        end = rest.length
    var spec = rest.slice(0, end)
    var parts = spec.split(",")
    return {
        start: parseInt(parts[0], 10) || 1,
        count: parts.length > 1 ? (parseInt(parts[1], 10) || 0) : 1
    }
}

function hunkHasSecret(hunk, isSecretLine) {
    for (var i = 0; i < hunk.lines.length; i++) {
        var line = hunk.lines[i]
        if (line.charAt(0) === "+" && line.indexOf("+++") !== 0 && isSecretLine(line.slice(1)))
            return true
    }
    return false
}

function hunkHasDeletion(hunk) {
    for (var i = 0; i < hunk.lines.length; i++) {
        var line = hunk.lines[i]
        if (line.charAt(0) === "-" && line.indexOf("---") !== 0)
            return true
    }
    return false
}

function secretRunsFromHunk(hunk, isSecretLine) {
    var parsed = parseHunkHeader(hunk.header)
    var newLine = parsed.start
    var runs = []
    var runStart = null
    var runLines = []
    function flush() {
        if (runStart === null || !runLines.length)
            return
        runs.push({
            header: "@@ -0,0 +" + runStart + "," + runLines.length + " @@",
            lines: runLines.slice()
        })
        runStart = null
        runLines = []
    }
    for (var i = 0; i < hunk.lines.length; i++) {
        var line = hunk.lines[i]
        if (line.indexOf("+++") === 0)
            continue
        if (line.charAt(0) === "+") {
            if (isSecretLine(line.slice(1))) {
                if (runStart === null)
                    runStart = newLine
                runLines.push(line)
            } else {
                flush()
            }
            newLine += 1
        } else if (line.charAt(0) === "-") {
            flush()
        } else {
            flush()
            newLine += 1
        }
    }
    flush()
    return runs
}

function filterPatch(diffText, isSecretLine, onlyFile) {
    var files = parseDiff(diffText)
    var keptFiles = []
    var fallbackFiles = []
    var want = onlyFile ? String(onlyFile) : ""
    for (var i = 0; i < files.length; i++) {
        var file = files[i]
        if (want && file.path !== want)
            continue
        if (file.binary) {
            if (want && file.path === want)
                fallbackFiles.push(file.path)
            continue
        }
        var kept = []
        var mustFallback = false
        for (var j = 0; j < file.hunks.length; j++) {
            if (!hunkHasSecret(file.hunks[j], isSecretLine))
                continue
            if (hunkHasDeletion(file.hunks[j])) {
                mustFallback = true
                continue
            }
            var runs = secretRunsFromHunk(file.hunks[j], isSecretLine)
            for (var r = 0; r < runs.length; r++)
                kept.push(runs[r])
        }
        if (mustFallback)
            fallbackFiles.push(file.path)
        else if (kept.length)
            keptFiles.push({ header: file.header, path: file.path, hunks: kept })
    }
    return { files: keptFiles, fallbackFiles: fallbackFiles, patch: renderPatch(keptFiles) }
}

function renderPatch(files) {
    var out = []
    for (var i = 0; i < files.length; i++) {
        var file = files[i]
        for (var h = 0; h < file.header.length; h++)
            out.push(file.header[h])
        for (var j = 0; j < file.hunks.length; j++) {
            var hunk = file.hunks[j]
            out.push(hunk.header)
            for (var k = 0; k < hunk.lines.length; k++)
                out.push(hunk.lines[k])
        }
    }
    if (!out.length)
        return ""
    var text = out.join("\n")
    if (text.charAt(text.length - 1) !== "\n")
        text += "\n"
    return text
}

function secretLinePredicate(scanFn, opts) {
    return function (line) {
        var hits = scanFn(line, opts || { src: "git" })
        if (!hits || !hits.length)
            return false
        for (var i = 0; i < hits.length; i++) {
            if (hits[i].tier === 1)
                return true
        }
        return false
    }
}

function plan(diffText, scanFn, opts) {
    var pred = secretLinePredicate(scanFn, opts)
    var onlyFile = opts && opts.file ? opts.file : null
    var filtered = filterPatch(diffText, pred, onlyFile)
    var files = []
    for (var i = 0; i < filtered.files.length; i++)
        files.push(filtered.files[i].path)
    return {
        mode: filtered.patch ? "surgical" : (filtered.fallbackFiles.length ? "unstaged-all" : "none"),
        patch: filtered.patch,
        files: files,
        fallbackFiles: filtered.fallbackFiles.slice(),
        label: filtered.patch ? "surgical hunk reverse" : (filtered.fallbackFiles.length ? fallbackLabel() : "nothing to redact")
    }
}

function fallbackLabel() {
    return "file unstaged (all hunks)"
}
