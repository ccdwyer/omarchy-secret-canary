.pragma library

// Shared live state for Service / Overlay / BarWidget in one engine.
// Service is the writer. Overlay and the chip poll snapshot().

var PLUGIN_ID = "io.github.chris.secret-canary"
var revision = 0
var helper = "unknown"
var clipboardMode = "unknown"
var gitMode = "idle"
var watching = false
var degraded = false
var mutedUntil = 0
var sound = false
var hideUntilEvent = false
var hadEvent = false
var repos = []
var allowCount = 0
var disabledRules = []
var lastIncident = null
var lastStatusNote = ""
var lastResult = null
var barLevel = "green"
var overlayOpen = false

function snapshot() {
    return {
        pluginId: PLUGIN_ID,
        revision: revision,
        helper: helper,
        clipboardMode: clipboardMode,
        gitMode: gitMode,
        watching: watching,
        degraded: degraded,
        mutedUntil: mutedUntil,
        muted: isMuted(),
        sound: sound,
        hideUntilEvent: hideUntilEvent,
        hadEvent: hadEvent,
        repos: repos.slice(),
        allowCount: allowCount,
        disabledRules: disabledRules.slice(),
        lastIncident: lastIncident ? copyIncident(lastIncident) : null,
        lastStatusNote: lastStatusNote,
        lastResult: lastResult,
        barLevel: barLevel,
        overlayOpen: overlayOpen
    }
}

function copyIncident(inc) {
    return {
        type: inc.type,
        src: inc.src,
        rule: inc.rule,
        title: inc.title,
        tier: inc.tier,
        redacted_preview: inc.redacted_preview,
        actions: (inc.actions || []).slice(),
        file: inc.file || null,
        repo: inc.repo || null,
        hash: inc.hash || "",
        note: inc.note || "",
        at: inc.at || 0
    }
}

function bump() {
    revision += 1
}

function isMuted(now) {
    var t = now || Date.now()
    return mutedUntil > t
}

function applyStatus(ev) {
    if (!ev)
        return
    if (ev.helper)
        helper = ev.helper
    if (ev.clipboard)
        clipboardMode = ev.clipboard
    if (ev.git)
        gitMode = ev.git
    if (ev.watching !== undefined)
        watching = !!ev.watching
    if (ev.degraded !== undefined)
        degraded = !!ev.degraded
    if (ev.note)
        lastStatusNote = ev.note
    if (ev.repos !== undefined && typeof ev.repos === "number") {
        // count only; repo list arrives via type=repos
    }
    if (ev.muted === false)
        mutedUntil = 0
    recomputeBar()
    bump()
}

function applyAlert(ev) {
    if (!ev)
        return
    hadEvent = true
    lastIncident = copyIncident(ev)
    lastIncident.at = Date.now()
    recomputeBar()
    bump()
}

function applyResult(ev) {
    lastResult = ev || null
    bump()
}

function setRepos(list) {
    repos = []
    var src = list || []
    for (var i = 0; i < src.length; i++)
        repos.push(String(src[i]))
    bump()
}

function setAllow(count, rules) {
    allowCount = Number(count) || 0
    disabledRules = []
    var src = rules || []
    for (var i = 0; i < src.length; i++)
        disabledRules.push(String(src[i]))
    bump()
}

function setMutedUntil(ts) {
    mutedUntil = Number(ts) || 0
    recomputeBar()
    bump()
}

function setSound(v) {
    sound = !!v
    bump()
}

function setHideUntilEvent(v) {
    hideUntilEvent = !!v
    bump()
}

function setOverlayOpen(v) {
    overlayOpen = !!v
    bump()
}

function clearIncident() {
    lastIncident = null
    recomputeBar()
    bump()
}

function recomputeBar() {
    if (lastIncident && Number(lastIncident.tier) === 1 && lastIncident.type === "alert") {
        barLevel = "red"
        return
    }
    if (degraded || helper === "missing") {
        barLevel = "amber"
        return
    }
    if (lastIncident && Number(lastIncident.tier) > 1 && lastIncident.src !== "git") {
        barLevel = "amber"
        return
    }
    if (isMuted()) {
        barLevel = "green"
        return
    }
    barLevel = watching ? "green" : "amber"
}

function pluginId() {
    return PLUGIN_ID
}
