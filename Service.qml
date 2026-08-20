import QtQuick
import Quickshell
import Quickshell.Io
import "js/Protocol.js" as Protocol
import "js/State.js" as State

Item {
  id: root
  property string moduleName: "io.github.chris.secret-canary"

  property var shell: null
  property var manifest: null
  property var pluginRegistry: null
  property string omarchyPath: Quickshell.env("OMARCHY_PATH") || ""
  property bool sound: false
  property bool hideUntilEvent: false

  Adapter { id: adapter }

  readonly property string pluginId: adapter.pluginId
  readonly property string pluginDir: adapter.pluginDirFrom(manifest, Qt.resolvedUrl("."))
  readonly property string daemonBin: pluginDir + "/bin/canaryd"
  readonly property string daemonSh: pluginDir + "/compat/canaryd.sh"
  readonly property string patternsPath: pluginDir + "/patterns/rules.toml"

  property string helperPath: ""
  property bool helperIsBinary: false
  property bool helperReady: false
  property bool degraded: false
  property int restarts: 0
  readonly property int maxRestarts: 3
  property string lastStatus: "starting"
  property var lastIncident: null
  property int stateRevision: 0
  property string barLevel: "amber"
  property bool watching: false
  property string clipboardMode: "unknown"
  property string gitMode: "idle"
  property bool muted: false
  property var repos: []
  property int allowCount: 0
  property string lastNote: ""
  property string lastResultLabel: ""
  property bool overlayWanted: false

  function publish() {
    root.stateRevision = State.snapshot().revision
    root.barLevel = State.snapshot().barLevel
    root.watching = State.snapshot().watching
    root.muted = State.snapshot().muted
    root.lastIncident = State.snapshot().lastIncident
    root.repos = State.snapshot().repos
    root.allowCount = State.snapshot().allowCount
    root.lastNote = State.snapshot().lastStatusNote
    root.lastResultLabel = State.snapshot().lastResult ? (State.snapshot().lastResult.label || "") : ""
  }

  function send(cmd, fields) {
    if (!daemon.running)
      return false
    return adapter.writeDaemon(daemon, Protocol.command(cmd, fields || {}))
  }

  function summonOverlay(payload) {
    root.overlayWanted = true
    State.setOverlayOpen(true)
    root.publish()
    adapter.summon(root.shell, payload || "{}")
    return "ok"
  }

  function hideOverlay() {
    root.overlayWanted = false
    State.setOverlayOpen(false)
    root.publish()
    adapter.hide(root.shell)
    return "ok"
  }

  function onDaemonLine(line) {
    var ev = Protocol.parseLine(line)
    if (!ev)
      return
    if (ev.type === "status") {
      root.clipboardMode = ev.clipboard || root.clipboardMode
      root.gitMode = ev.git || root.gitMode
      root.degraded = !!ev.degraded
      root.watching = ev.watching !== false
      State.applyStatus(ev)
      root.publish()
      return
    }
    if (ev.type === "ready") {
      root.lastStatus = "ready"
      State.applyStatus({ watching: true, helper: ev.helper || (root.helperIsBinary ? "canaryd" : "canaryd.sh") })
      root.send("status")
      root.publish()
      return
    }
    if (ev.type === "repos") {
      State.setRepos(ev.paths || [])
      root.publish()
      return
    }
    if (ev.type === "allowlist") {
      State.setAllow(ev.values || 0, ev.rules || [])
      root.publish()
      return
    }
    if (ev.type === "result") {
      State.applyResult(ev)
      root.lastResultLabel = ev.label || ""
      root.publish()
      if (ev.ok === false)
        return
      if (ev.cmd === "restore-clip" || ev.cmd === "dismiss" || ev.cmd === "redact-clip" || ev.cmd === "redact-git")
        Qt.callLater(root.hideOverlay)
      return
    }
    if (ev.type === "info") {
      State.applyStatus({ note: ev.note || "" })
      root.publish()
      return
    }
    if (ev.type === "log")
      return
    if (ev.type === "alert")
      root.handleAlert(ev)
  }

  function handleAlert(ev) {
    State.applyAlert(ev)
    root.lastIncident = State.snapshot().lastIncident
    root.publish()
    if (Protocol.shouldSummonOverlay(ev, State.isMuted())) {
      if (root.sound)
        adapter.chime()
      var payload = JSON.stringify(Protocol.alertEvent(ev))
      root.summonOverlay(payload)
    }
  }

  function startHelper() {
    var path = root.helperPath
    if (!path) {
      root.degraded = true
      root.lastStatus = "missing"
      State.applyStatus({ watching: false, degraded: true, helper: "missing", clipboard: "unavailable" })
      root.publish()
      return
    }
    healthyTimer.stop()
    daemon.command = [path, "--patterns", root.patternsPath]
    daemon.running = true
    root.lastStatus = "starting"
  }

  function onHelperGone() {
    healthyTimer.stop()
    root.restarts += 1
    if (root.restarts <= root.maxRestarts && root.helperIsBinary) {
      restartTimer.restart()
      return
    }
    if (root.helperIsBinary && root.restarts > root.maxRestarts) {
      root.helperIsBinary = false
      root.helperPath = root.daemonSh
      root.restarts = 0
      restartTimer.restart()
      return
    }
    root.degraded = true
    root.lastStatus = "degraded"
    State.applyStatus({ watching: false, degraded: true, helper: "missing", clipboard: "unavailable" })
    root.publish()
  }

  function incidentSrc() {
    if (root.lastIncident && root.lastIncident.src)
      return String(root.lastIncident.src)
    var snap = State.snapshot()
    if (snap.lastIncident && snap.lastIncident.src)
      return String(snap.lastIncident.src)
    return ""
  }

  function incidentHash() {
    if (root.lastIncident && root.lastIncident.hash)
      return String(root.lastIncident.hash)
    var snap = State.snapshot()
    if (snap.lastIncident && snap.lastIncident.hash)
      return String(snap.lastIncident.hash)
    return ""
  }

  function sendOrFail(cmd, fields) {
    if (!root.send(cmd, fields || {}))
      return "failed"
    return "ok"
  }

  function redact() {
    var src = root.incidentSrc()
    var cmd = Protocol.redactCommand(src)
    if (!src)
      return "no-incident"
    return root.sendOrFail(cmd, { hash: root.incidentHash() })
  }
  function redactClip(hash) {
    return root.sendOrFail("redact-clip", { hash: String(hash || root.incidentHash()) })
  }
  function redactGit(hash) {
    return root.sendOrFail("redact-git", { hash: String(hash || root.incidentHash()) })
  }
  function restore() {
    if (root.incidentSrc() !== "clipboard")
      return "no-restore"
    return root.sendOrFail("restore-clip", {})
  }
  function allowlist(hash) {
    var r = root.sendOrFail("allowlist", { hash: String(hash || root.incidentHash()) })
    if (r === "ok")
      root.hideOverlay()
    return r
  }
  function allowRule(id) { return root.sendOrFail("allow-rule", { rule: String(id || "") }) }
  function enableRule(id) { return root.sendOrFail("enable-rule", { rule: String(id || "") }) }
  function dismiss() {
    var r = root.sendOrFail("dismiss", {})
    root.hideOverlay()
    State.clearIncident()
    root.publish()
    return r
  }
  function mute() {
    var r = root.sendOrFail("mute", { seconds: 3600 })
    if (r === "ok") {
      State.setMutedUntil(Date.now() + 3600000)
      root.publish()
    }
    return r
  }
  function unmute() {
    var r = root.sendOrFail("unmute", {})
    if (r === "ok") {
      State.setMutedUntil(0)
      root.publish()
    }
    return r
  }
  function testCanary() { return root.sendOrFail("test", {}) }
  function watchRepo(path) { return root.sendOrFail("watch", { path: String(path || "") }) }
  function unwatchRepo(path) { return root.sendOrFail("unwatch", { path: String(path || "") }) }
  function ping() { return "ok" }
  function status() {
    return JSON.stringify({
      id: root.pluginId,
      helper: root.helperPath,
      binary: root.helperIsBinary,
      degraded: root.degraded,
      watching: root.watching,
      clipboard: root.clipboardMode,
      git: root.gitMode,
      bar: root.barLevel,
      muted: root.muted,
      sound: root.sound
    })
  }
  function open() { return root.summonOverlay(root.lastIncident ? JSON.stringify(root.lastIncident) : "{}") }
  function close() { return root.hideOverlay() }
  function toggle() {
    if (root.overlayWanted)
      return root.hideOverlay()
    return root.open()
  }
  function setSound(v) { root.sound = v === true || v === "true" || v === 1; State.setSound(root.sound); root.publish(); return "ok" }
  function settings() { return root.summonOverlay("{\"mode\":\"settings\"}") }

  Process {
    id: whichProc
    command: ["sh", "-c", "if [ ! -x \"$1\" ]; then echo missing; exit 0; fi; h=$(od -An -tx1 -N2 \"$1\" 2>/dev/null | tr -d ' \\n'); if [ \"$h\" = \"2321\" ]; then echo missing; else echo binary; fi", "sh", root.daemonBin]
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var out = String(text || "").trim()
        if (out === "binary") {
          root.helperIsBinary = true
          root.helperPath = root.daemonBin
        } else {
          root.helperIsBinary = false
          root.helperPath = root.daemonSh
        }
        root.helperReady = true
        root.startHelper()
      }
    }
  }

  Process {
    id: daemon
    running: false
    stdinEnabled: true
    stdout: SplitParser {
      onRead: function(line) { root.onDaemonLine(line) }
    }
    stderr: SplitParser {
      onRead: function(line) { console.warn("canaryd:", line) }
    }
    onStarted: healthyTimer.restart()
    onExited: {
      root.lastStatus = "exited:" + exitCode
      root.onHelperGone()
    }
  }

  Timer {
    id: restartTimer
    interval: 400
    repeat: false
    onTriggered: root.startHelper()
  }

  Timer {
    id: healthyTimer
    interval: 30000
    repeat: false
    onTriggered: {
      if (daemon.running)
        root.restarts = 0
    }
  }

  IpcHandler {
    target: "io.github.chris.secret-canary"

    function ping(): string { return root.ping() }
    function status(): string { return root.status() }
    function redact(): string { return root.redact() }
    function redactClip(hash: string): string { return root.redactClip(hash) }
    function redactGit(hash: string): string { return root.redactGit(hash) }
    function restore(): string { return root.restore() }
    function allowlist(hash: string): string { return root.allowlist(hash) }
    function allowRule(id: string): string { return root.allowRule(id) }
    function enableRule(id: string): string { return root.enableRule(id) }
    function dismiss(): string { return root.dismiss() }
    function mute(): string { return root.mute() }
    function unmute(): string { return root.unmute() }
    function test(): string { return root.testCanary() }
    function watch(path: string): string { return root.watchRepo(path) }
    function unwatch(path: string): string { return root.unwatchRepo(path) }
    function summon(): string { return root.open() }
    function open(): string { return root.open() }
    function close(): string { return root.close() }
    function toggle(): string { return root.toggle() }
    function settings(): string { return root.settings() }
    function setSound(v: string): string { return root.setSound(v === "true") }
  }

  Component.onCompleted: {
    State.setSound(root.sound)
    State.setHideUntilEvent(root.hideUntilEvent)
    whichProc.running = true
    root.publish()
  }
}
