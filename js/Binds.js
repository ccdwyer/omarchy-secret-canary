.pragma library

// Detect live Hyprland binds and plan a bindings.lua snippet.
// Lua binds show up as dispatcher "__lua" with a description, not the
// omarchy-shell command in `arg`, so "ours" is plugin-id in arg OR our
// descriptions.
// Writes happen only on an explicit Set/Change/Remove click. Never
// hl.unbind — install-binds.py edits only this plugin's marked block.

var PLUGIN_ID = "io.github.chris.secret-canary"
var SUPER = 64
var SHIFT = 1
var CTRL = 4
var ALT = 8

var CANDIDATES = [
    {
        keys: "SUPER + ALT + X",
        modmask: SUPER + ALT,
        key: "X",
        desc: "Secret Canary redact",
        cmd: "omarchy-shell io.github.chris.secret-canary redact ''",
        alternates: [
            { keys: "SUPER + SHIFT + ALT + X", modmask: SUPER + SHIFT + ALT, key: "X" }
        ]
    },
    {
        keys: "SUPER + ALT + SHIFT + C",
        modmask: SUPER + ALT + SHIFT,
        key: "C",
        desc: "Secret Canary",
        cmd: "omarchy-shell shell summon io.github.chris.secret-canary '{}'",
        alternates: [
            { keys: "SUPER + ALT + C", modmask: SUPER + ALT, key: "C" }
        ]
    }
]

var offer = {
    needed: true,
    note: "",
    current: "",
    already: 0,
    toAdd: [],
    skipped: [],
    ours: []
}

function setOffer(next) {
    offer = next || offer
}

function parseBinds(raw) {
    if (!raw)
        return []
    var data = raw
    if (typeof raw === "string") {
        try {
            data = JSON.parse(raw)
        } catch (e) {
            return []
        }
    }
    return data && data.length ? data : []
}

function keyOf(bind) {
    return String((bind && bind.key) || "").toUpperCase()
}

function keysMatch(a, b) {
    var x = String(a || "").toUpperCase()
    var y = String(b || "").toUpperCase()
    if (x === y)
        return true
    function isPeriod(k) { return k === "PERIOD" || k === "." }
    return isPeriod(x) && isPeriod(y)
}

function keysFromBind(bind) {
    var m = Number(bind && bind.modmask) || 0
    var parts = []
    if (m & SUPER)
        parts.push("SUPER")
    if (m & SHIFT)
        parts.push("SHIFT")
    if (m & CTRL)
        parts.push("CTRL")
    if (m & ALT)
        parts.push("ALT")
    var key = keyOf(bind)
    if (key)
        parts.push(key)
    return parts.join(" + ")
}

function isOurs(bind) {
    if (!bind)
        return false
    var arg = String(bind.arg || "")
    var desc = String(bind.description || "")
    if (arg.indexOf(PLUGIN_ID) >= 0)
        return true
    for (var i = 0; i < CANDIDATES.length; i++) {
        if (desc === CANDIDATES[i].desc)
            return true
    }
    return false
}

function oursEntries(binds) {
    var out = []
    var seen = {}
    var list = binds || []
    for (var i = 0; i < list.length; i++) {
        if (!isOurs(list[i]))
            continue
        var keys = keysFromBind(list[i])
        var desc = String(list[i].description || "")
        var id = keys + "\0" + desc
        if (seen[id])
            continue
        seen[id] = true
        out.push({ keys: keys, desc: desc })
    }
    return out
}

function oursCount(binds) {
    return oursEntries(binds).length
}

function currentLabel(entries) {
    var list = entries || []
    if (!list.length)
        return ""
    return list.map(function(e) {
        return e.desc ? (e.keys + " — " + e.desc) : e.keys
    }).join(" · ")
}

function comboOwner(binds, modmask, key) {
    var want = String(key || "").toUpperCase()
    var list = binds || []
    for (var i = 0; i < list.length; i++) {
        var b = list[i]
        if (Number(b.modmask) !== Number(modmask))
            continue
        if (!keysMatch(keyOf(b), want))
            continue
        if (isOurs(b))
            return { ours: true, desc: String(b.description || "") }
        return { ours: false, desc: String(b.description || b.dispatcher || "already bound") }
    }
    return null
}

function pickCombo(binds, candidate) {
    var owner = comboOwner(binds, candidate.modmask, candidate.key)
    if (!owner)
        return { keys: candidate.keys, modmask: candidate.modmask, key: candidate.key, desc: candidate.desc, cmd: candidate.cmd, chosen: candidate.keys }
    if (owner.ours)
        return { already: true, keys: candidate.keys, chosen: candidate.keys, desc: candidate.desc, cmd: candidate.cmd }
    var alts = candidate.alternates || []
    for (var i = 0; i < alts.length; i++) {
        var a = alts[i]
        var altOwner = comboOwner(binds, a.modmask, a.key)
        if (!altOwner)
            return {
                keys: a.keys,
                modmask: a.modmask,
                key: a.key,
                desc: candidate.desc,
                cmd: candidate.cmd,
                chosen: a.keys,
                preferred: candidate.keys,
                conflict: owner.desc
            }
        if (altOwner.ours)
            return {
                already: true,
                keys: a.keys,
                chosen: a.keys,
                desc: candidate.desc,
                cmd: candidate.cmd,
                preferred: candidate.keys,
                conflict: owner.desc
            }
    }
    return { skipped: true, keys: candidate.keys, desc: candidate.desc, conflict: owner.desc }
}

function writeItem(pick, candidate) {
    return {
        keys: pick.chosen || pick.keys || candidate.keys,
        chosen: pick.chosen || pick.keys || candidate.keys,
        desc: pick.desc || candidate.desc,
        cmd: pick.cmd || candidate.cmd
    }
}

function plan(binds, opts) {
    opts = opts || {}
    var replace = !!opts.replace
    var toAdd = []
    var skipped = []
    var already = 0
    for (var i = 0; i < CANDIDATES.length; i++) {
        var candidate = CANDIDATES[i]
        var pick = pickCombo(binds, candidate)
        if (pick.already) {
            already++
            if (replace)
                toAdd.push(writeItem(pick, candidate))
        } else if (pick.skipped)
            skipped.push(pick)
        else
            toAdd.push(pick)
    }
    var ours = oursEntries(binds)
    if (ours.length > 0)
        already = Math.max(already, ours.length)
    var needed = ours.length === 0
    if (!needed && !replace)
        toAdd = []
    var current = currentLabel(ours)
    var keys = ours.map(function(e) { return e.keys }).join(" · ")
    var note = ""
    if (!needed)
        note = current
    else if (!toAdd.length && skipped.length)
        note = skipped.map(function(s) { return s.keys + " is " + (s.conflict || "taken") }).join("; ")
    else if (toAdd.length) {
        var bits = toAdd.map(function(p) { return p.chosen || p.keys })
        note = "Set " + bits.join(", ")
        for (var s = 0; s < skipped.length; s++)
            note += " — skipped " + skipped[s].keys + " (" + skipped[s].conflict + ")"
    }
    return {
        needed: needed,
        already: already,
        toAdd: toAdd,
        skipped: skipped,
        note: note,
        current: current,
        keys: keys,
        ours: ours
    }
}

function luaLine(item) {
    var keys = String(item.chosen || item.keys || "").replace(/"/g, "")
    var desc = String(item.desc || "").replace(/"/g, "")
    var cmd = String(item.cmd || "").replace(/"/g, '\\"')
    return "o.bind(\"" + keys + "\", \"" + desc + "\", \"" + cmd + "\")"
}

function luaBlock(items) {
    var lines = []
    var list = items || []
    for (var i = 0; i < list.length; i++)
        lines.push(luaLine(list[i]))
    return lines.join("\n")
}

function applyScan(raw, opts) {
    var p = plan(parseBinds(raw), opts)
    setOffer(p)
    return p
}

function installArgv(pluginDir, pluginId, lua) {
    return ["python3", String(pluginDir || "") + "/compat/install-binds.py", String(pluginId || PLUGIN_ID), String(lua || "")]
}

function removeArgv(pluginDir, pluginId) {
    return ["python3", String(pluginDir || "") + "/compat/install-binds.py", "--remove", String(pluginId || PLUGIN_ID)]
}

function notifyBody(items, skipped) {
    var lines = []
    var list = items || []
    for (var i = 0; i < list.length; i++) {
        var it = list[i]
        lines.push((it.chosen || it.keys) + " — " + it.desc)
    }
    var miss = skipped || []
    for (var s = 0; s < miss.length; s++)
        lines.push("skipped " + miss[s].keys + " (" + (miss[s].conflict || "taken") + ")")
    return lines.join("\n")
}

function notifyArgv(appName, headline, body) {
    return ["omarchy", "notification", "send", "--app-name", String(appName || PLUGIN_ID), "-g", "󰌌", String(headline || "Keybindings"), String(body || "")]
}
