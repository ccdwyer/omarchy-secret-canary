.pragma library

// Allowlist of SHA-256(value) plus disabled rule ids.
// Stores hashes, never plaintext. Mirrors src/canaryd/src/allow.rs.

var REDACT_STRING = "[REDACTED by Secret Canary]"
var RESTORE_WINDOW_MS = 60000

function empty() {
    return {
        version: 1,
        values: [],
        rules: []
    }
}

function load(raw) {
    var data = raw
    if (typeof raw === "string") {
        try {
            data = JSON.parse(raw)
        } catch (e) {
            return empty()
        }
    }
    if (!data || typeof data !== "object")
        return empty()
    var out = empty()
    var values = data.values || []
    var rules = data.rules || []
    var i
    for (i = 0; i < values.length; i++) {
        if (values[i])
            out.values.push(String(values[i]).toLowerCase())
    }
    for (i = 0; i < rules.length; i++) {
        if (rules[i])
            out.rules.push(String(rules[i]))
    }
    return out
}

function serialize(store) {
    var s = store || empty()
    return JSON.stringify({
        version: 1,
        values: (s.values || []).slice(),
        rules: (s.rules || []).slice()
    })
}

function sha256Hex(text, hasher) {
    if (typeof hasher === "function")
        return hasher(String(text || ""))
    return ""
}

function addValue(store, hex) {
    var h = String(hex || "").toLowerCase()
    if (!h)
        return store
    if (!store.values)
        store.values = []
    if (store.values.indexOf(h) < 0)
        store.values.push(h)
    return store
}

function addRule(store, id) {
    var r = String(id || "")
    if (!r)
        return store
    if (!store.rules)
        store.rules = []
    if (store.rules.indexOf(r) < 0)
        store.rules.push(r)
    return store
}

function removeValue(store, hex) {
    var h = String(hex || "").toLowerCase()
    store.values = (store.values || []).filter(function (x) { return x !== h })
    return store
}

function removeRule(store, id) {
    var r = String(id || "")
    store.rules = (store.rules || []).filter(function (x) { return x !== r })
    return store
}

function valueSet(store) {
    var out = {}
    var list = (store && store.values) || []
    for (var i = 0; i < list.length; i++)
        out[list[i]] = true
    return out
}

function ruleSet(store) {
    var out = {}
    var list = (store && store.rules) || []
    for (var i = 0; i < list.length; i++)
        out[list[i]] = true
    return out
}

function isAllowedHash(store, hex) {
    return !!(valueSet(store)[String(hex || "").toLowerCase()])
}

function isRuleDisabled(store, id) {
    return !!(ruleSet(store)[String(id || "")])
}

function suppression() {
    return {
        permanent: {},
        recentRedact: {}
    }
}

function rememberRedact(sup, hash, now) {
    // Secret hash lives only in the 60s map so a clipboard-manager
    // re-injection can still warn. The redaction marker is permanent.
    sup.recentRedact[hash] = now || Date.now()
    return sup
}

function suppressMarker(sup, hash) {
    sup.permanent[hash] = true
    return sup
}

function permanentlySuppressed(sup, hash) {
    return !!(sup && sup.permanent && sup.permanent[hash])
}

function restoredByManager(sup, hash, now) {
    if (!sup || !sup.recentRedact)
        return false
    var ts = sup.recentRedact[hash]
    if (!ts)
        return false
    return (now || Date.now()) - ts <= RESTORE_WINDOW_MS
}

function redactString() {
    return REDACT_STRING
}

function restoreWindowMs() {
    return RESTORE_WINDOW_MS
}
