import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "js/State.js" as State

BarWidget {
  id: root
  moduleName: "io.github.chris.secret-canary"

  property bool sound: false
  property bool hideUntilEvent: false

  property string level: "green"
  property bool hadEvent: false
  property bool muted: false
  property bool degraded: false
  property bool watching: false
  property string lastTitle: ""
  property var repos: []
  property int allowCount: 0
  property string note: ""
  property bool bindNeeded: true
  property bool bindCanSet: false
  property string bindNote: ""
  property string bindCurrent: ""
  property string bindKeys: ""

  Adapter { id: adapter }

  readonly property var canaryService: adapter.findService(bar && bar.shell, null, bar)

  readonly property color danger: adapter.dangerColor(Color)
  readonly property color warning: adapter.warningColor(Color)
  readonly property color ok: adapter.okColor(Color)
  readonly property color bird: {
    if (root.level === "red")
      return root.danger
    if (root.level === "amber")
      return root.warning
    return root.ok
  }

  readonly property bool opened: false

  function refresh() {
    var snap = State.snapshot()
    root.level = snap.barLevel
    root.hadEvent = snap.hadEvent
    root.muted = snap.muted
    root.degraded = snap.degraded
    root.watching = snap.watching
    root.repos = snap.repos
    root.allowCount = snap.allowCount
    root.note = snap.lastStatusNote || ""
    root.lastTitle = snap.lastIncident ? (snap.lastIncident.title || "") : ""
    root.bindNeeded = !!snap.bindNeeded
    root.bindCanSet = !!snap.bindCanSet
    root.bindNote = snap.bindNote || ""
    root.bindCurrent = snap.bindCurrent || ""
    root.bindKeys = snap.bindKeys || ""
    State.setSound(root.sound)
    State.setHideUntilEvent(root.hideUntilEvent)
  }

  function callSvc(method, arg) {
    var svc = root.canaryService
    if (svc) {
      if (method === "testCanary" && typeof svc.testCanary === "function") return svc.testCanary()
      if (method === "mute" && typeof svc.mute === "function") return svc.mute()
      if (method === "unmute" && typeof svc.unmute === "function") return svc.unmute()
      if (method === "watchRepo" && typeof svc.watchRepo === "function") return svc.watchRepo(arg)
      if (method === "unwatchRepo" && typeof svc.unwatchRepo === "function") return svc.unwatchRepo(arg)
      if (method === "open" && typeof svc.open === "function") return svc.open()
      if (method === "setSound" && typeof svc.setSound === "function") return svc.setSound(arg)
      if (method === "dismiss" && typeof svc.dismiss === "function") return svc.dismiss()
      if (method === "settings" && typeof svc.settings === "function") return svc.settings()
      if (method === "installBinds" && typeof svc.installBinds === "function") return svc.installBinds(arg)
      if (method === "removeBinds" && typeof svc.removeBinds === "function") return svc.removeBinds(arg)
    }
    adapter.callIpc(bar && bar.shell, method, arg)
  }

  function open() {
    if (root.level === "red")
      root.callSvc("open", "")
    else
      root.callSvc("settings", "")
  }
  function close() {}
  function toggle() { root.open() }

  visible: !root.hideUntilEvent || root.hadEvent || root.level === "red" || root.degraded || root.bindNeeded
  implicitWidth: visible ? row.implicitWidth : 0
  implicitHeight: row.implicitHeight

  Timer {
    interval: 250
    running: true
    repeat: true
    onTriggered: root.refresh()
  }

  Row {
    id: row
    spacing: Style.space(4)

  WidgetButton {
    id: button
    bar: root.bar
    text: ""
    tooltipText: {
      var hotkey = root.bindNeeded
                   ? (root.bindCanSet ? "no hotkey — click Set hotkey" : (root.bindNote || "no hotkey"))
                   : (root.bindCurrent || "hotkey set")
      if (root.level === "red")
        return (root.lastTitle || "Secret Canary — alarm") + " · " + hotkey
      if (root.degraded)
        return "Secret Canary — degraded, not fully watching · " + hotkey
      if (root.muted)
        return "Secret Canary — muted · " + hotkey
      if (root.level === "amber")
        return (root.lastTitle || "Secret Canary — warning") + " · " + hotkey
      return "Secret Canary — watching · " + hotkey
    }
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.LeftButton)
        root.toggle()
      else if (buttonCode === Qt.RightButton)
        root.callSvc("testCanary", "")
    }

    Canvas {
      id: birdCanvas
      anchors.centerIn: parent
      width: Style.space(16)
      height: Style.space(16)
      onPaint: {
        var ctx = getContext("2d")
        ctx.reset()
        ctx.fillStyle = root.bird
        ctx.beginPath()
        ctx.ellipse(7, 8, 6, 5, 0, 0, Math.PI * 2)
        ctx.fill()
        ctx.beginPath()
        ctx.moveTo(12.5, 7.5)
        ctx.lineTo(16, 8.5)
        ctx.lineTo(12.5, 9.5)
        ctx.closePath()
        ctx.fill()
        ctx.beginPath()
        ctx.ellipse(5.2, 6.6, 1.1, 1.1, 0, 0, Math.PI * 2)
        ctx.fillStyle = "#111"
        ctx.fill()
      }
      Connections {
        target: root
        function onBirdChanged() { birdCanvas.requestPaint() }
      }
    }
  }

    WidgetButton {
      id: hotkeyButton
      visible: root.bindNeeded || root.bindCurrent.length > 0
      bar: root.bar
      text: root.bindNeeded ? "Set hotkey" : (root.bindKeys || "hotkey")
      tooltipText: {
        if (root.bindNeeded && root.bindCanSet)
          return root.bindNote.length ? root.bindNote : "Set Super+Alt+X redact / Super+Alt+Shift+C summon. Occupied combos are skipped. Never unbinds someone else's key."
        if (root.bindNeeded)
          return root.bindNote.length ? root.bindNote : "No free combo to assign"
        return (root.bindCurrent || "hotkey set") + " — left: change · right: remove"
      }
      onPressed: function(buttonCode) {
        if (root.bindNeeded) {
          if (buttonCode === Qt.LeftButton && root.bindCanSet)
            root.callSvc("installBinds", "")
          return
        }
        if (buttonCode === Qt.LeftButton)
          root.callSvc("installBinds", "change")
        else if (buttonCode === Qt.RightButton)
          root.callSvc("removeBinds", "")
      }
    }
  }

  Component.onCompleted: {
    if (root.canaryService && typeof root.canaryService.setSound === "function")
      root.canaryService.setSound(root.sound)
    root.refresh()
  }
}
