import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import qs.Commons
import qs.Ui
import "js/Protocol.js" as Protocol
import "js/State.js" as State

Item {
  id: root
  property string moduleName: "io.github.chris.secret-canary"

  property var shell: null
  property var manifest: null
  property var pluginRegistry: null
  property string omarchyPath: Quickshell.env("OMARCHY_PATH") || ""
  property bool opened: false
  property string mode: "alarm"
  property string pluginId: "io.github.chris.secret-canary"

  property string incidentTitle: ""
  property string incidentSrc: ""
  property string incidentRule: ""
  property int incidentTier: 1
  property string incidentPreview: ""
  property string incidentFile: ""
  property string incidentRepo: ""
  property string incidentNote: ""
  property string incidentHash: ""
  property var incidentActions: []
  property string resultLabel: ""
  property var repos: []
  property var disabledRules: []
  property var ruleCatalog: Protocol.ruleCatalog()
  property bool muted: false
  property int allowCount: 0
  property string statusLine: ""
  property string repoDraft: ""

  Adapter { id: adapter }

  property color danger: adapter.dangerColor(Color)
  property color warning: adapter.warningColor(Color)
  property color background: Color.menu.background
  property color foreground: Color.menu.text
  property color border: Color.menu.border
  property color accent: Color.accent
  property var borderSpec: Border.surfaceSpec("menu", "border", border, Math.max(1, Style.space(2)))
  readonly property int cornerRadius: Style.cornerRadius
  property string fontFamily: Style.font.menuFamily
  readonly property bool reduceMotion: adapter.reduceMotion(Style)
  readonly property int motionMs: reduceMotion ? 0 : 180
  property real washOpacity: 0.15

  function serviceRef() {
    return adapter.findService(root.shell, root.pluginRegistry, null)
  }

  function callService(method, arg) {
    var svc = root.serviceRef()
    if (svc) {
      if (method === "redact" && typeof svc.redact === "function") return svc.redact()
      if (method === "restore" && typeof svc.restore === "function") return svc.restore()
      if (method === "allowlist" && typeof svc.allowlist === "function") return svc.allowlist(arg)
      if (method === "dismiss" && typeof svc.dismiss === "function") return svc.dismiss()
      if (method === "mute" && typeof svc.mute === "function") return svc.mute()
      if (method === "unmute" && typeof svc.unmute === "function") return svc.unmute()
      if (method === "testCanary" && typeof svc.testCanary === "function") return svc.testCanary()
      if (method === "watchRepo" && typeof svc.watchRepo === "function") return svc.watchRepo(arg)
      if (method === "unwatchRepo" && typeof svc.unwatchRepo === "function") return svc.unwatchRepo(arg)
      if (method === "redactClip" && typeof svc.redactClip === "function") return svc.redactClip(arg)
      if (method === "redactGit" && typeof svc.redactGit === "function") return svc.redactGit(arg)
      if (method === "allowRule" && typeof svc.allowRule === "function") return svc.allowRule(arg)
      if (method === "enableRule" && typeof svc.enableRule === "function") return svc.enableRule(arg)
      if (method === "status" && typeof svc.status === "function") return svc.status()
      if (method === "installBinds" && typeof svc.installBinds === "function") return svc.installBinds(arg)
    }
    if (adapter.callIpc(root.shell, method, arg))
      return "ok"
    return "failed"
  }

  function requestHide() {
    root.close()
    adapter.hide(root.shell)
  }

  function clearIncidentView() {
    root.incidentTitle = ""
    root.incidentSrc = ""
    root.incidentRule = ""
    root.incidentTier = 1
    root.incidentPreview = ""
    root.incidentFile = ""
    root.incidentRepo = ""
    root.incidentNote = ""
    root.incidentHash = ""
    root.incidentActions = []
    root.resultLabel = ""
  }

  function applyIncident(inc) {
    if (!inc) {
      var snap = State.snapshot()
      inc = snap.lastIncident
    }
    if (!inc)
      return
    root.incidentTitle = inc.title || ""
    root.incidentSrc = inc.src || ""
    root.incidentRule = inc.rule || ""
    root.incidentTier = Number(inc.tier) || 1
    root.incidentPreview = inc.redacted_preview || ""
    root.incidentFile = inc.file || ""
    root.incidentRepo = inc.repo || ""
    root.incidentNote = inc.note || ""
    root.incidentHash = inc.hash || ""
    root.incidentActions = inc.actions || []
    var res = State.snapshot().lastResult
    root.resultLabel = res && res.label ? res.label : ""
  }

  function open(payloadJson) {
    root.opened = true
    root.mode = "alarm"
    try {
      var payload = payloadJson && String(payloadJson).length ? JSON.parse(payloadJson) : {}
      if (payload && payload.mode === "settings")
        root.mode = "settings"
      if (root.mode === "settings") {
        root.clearIncidentView()
        State.clearIncident()
      } else if (payload && (payload.rule || payload.title)) {
        root.applyIncident(payload)
      } else {
        root.applyIncident(null)
      }
    } catch (e) {
      if (root.mode === "settings")
        root.clearIncidentView()
      else
        root.applyIncident(null)
    }
    if (root.mode === "alarm")
      autoDismiss.restart()
    else
      autoDismiss.stop()
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function close() {
    root.opened = false
    autoDismiss.stop()
  }

  function toggle() {
    if (root.opened)
      root.close()
    else
      root.open("{}")
  }

  function redact(arg) { return String(root.callService("redact", arg || "")) }
  function restore(arg) { return String(root.callService("restore", arg || "")) }
  function status(arg) { return String(root.callService("status", arg || "")) }
  function mute(arg) { return String(root.callService("mute", arg || "")) }
  function test(arg) { return String(root.callService("testCanary", arg || "")) }
  function allowRule(arg) { return String(root.callService("allowRule", arg || "")) }
  function enableRule(arg) { return String(root.callService("enableRule", arg || "")) }
  function installBinds(arg) { return String(root.callService("installBinds", arg || "")) }

  function doRedact() {
    if (root.mode !== "alarm")
      return
    var r
    if (root.incidentSrc === "git")
      r = root.callService("redactGit", root.incidentHash)
    else
      r = root.callService("redactClip", root.incidentHash)
    if (r !== "failed")
      autoDismiss.stop()
  }

  function ruleIsDisabled(id) {
    var list = root.disabledRules || []
    for (var i = 0; i < list.length; i++) {
      if (list[i] === id)
        return true
    }
    return false
  }

  function toggleRule(id) {
    if (root.ruleIsDisabled(id))
      root.callService("enableRule", id)
    else
      root.callService("allowRule", id)
  }

  function doRestore() {
    if (root.mode !== "alarm")
      return
    if (!Protocol.canRestore(root.incidentSrc))
      return
    root.callService("restore", "")
  }

  function doAllow() {
    if (root.mode !== "alarm")
      return
    var r = root.callService("allowlist", root.incidentHash)
    if (r !== "failed")
      root.requestHide()
  }

  function doDismiss() {
    root.callService("dismiss", "")
    root.requestHide()
  }

  readonly property string keymap: {
    var git = root.incidentSrc === "git"
    var enter = git ? "Enter unstages the secret hunk" : "Enter redacts the clipboard"
    var restore = Protocol.canRestore(root.incidentSrc) ? "  ·  R restores previous clipboard" : ""
    return enter + restore + "  ·  A allowlists  ·  Esc dismisses"
  }

  Timer {
    id: autoDismiss
    interval: 30000
    repeat: false
    onTriggered: root.doDismiss()
  }

  Timer {
    interval: root.opened ? 120 : 800
    running: root.opened
    repeat: true
    onTriggered: {
      var snap = State.snapshot()
      root.repos = snap.repos || []
      root.disabledRules = snap.disabledRules || []
      root.muted = !!snap.muted
      root.allowCount = snap.allowCount || 0
      root.statusLine = snap.degraded ? "degraded" : (snap.watching ? "watching" : "starting")
      if (root.mode !== "alarm")
        return
      if (snap.lastResult && snap.lastResult.label)
        root.resultLabel = snap.lastResult.label
      if (snap.lastIncident)
        root.applyIncident(snap.lastIncident)
    }
  }

  PanelWindow {
    id: panel
    visible: root.opened
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    WlrLayershell.namespace: "secret-canary"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive
    exclusionMode: ExclusionMode.Ignore
    mask: Region { item: pill }

    Rectangle {
      id: wash
      anchors.fill: parent
      color: root.danger
      opacity: root.opened && root.mode === "alarm" ? root.washOpacity : 0
      Behavior on opacity { NumberAnimation { duration: root.motionMs } }
    }

    SequentialAnimation {
      running: root.opened && root.mode === "alarm" && !root.reduceMotion
      loops: Animation.Infinite
      NumberAnimation { target: root; property: "washOpacity"; from: 0.12; to: 0.20; duration: 900; easing.type: Easing.InOutQuad }
      NumberAnimation { target: root; property: "washOpacity"; from: 0.20; to: 0.12; duration: 900; easing.type: Easing.InOutQuad }
    }

    Rectangle { anchors.top: parent.top; anchors.left: parent.left; anchors.right: parent.right; height: 4; color: root.danger; opacity: root.opened ? 0.95 : 0 }
    Rectangle { anchors.bottom: parent.bottom; anchors.left: parent.left; anchors.right: parent.right; height: 4; color: root.danger; opacity: root.opened ? 0.95 : 0 }
    Rectangle { anchors.top: parent.top; anchors.bottom: parent.bottom; anchors.left: parent.left; width: 4; color: root.danger; opacity: root.opened ? 0.95 : 0 }
    Rectangle { anchors.top: parent.top; anchors.bottom: parent.bottom; anchors.right: parent.right; width: 4; color: root.danger; opacity: root.opened ? 0.95 : 0 }

    BorderSurface {
      id: pill
      width: Math.min(Style.space(640), panel.width - Style.gapsOut * 2)
      height: Math.min(pillCol.implicitHeight + Style.spacing.panelPadding * 2, panel.height * 0.72)
      radius: root.cornerRadius
      anchors.centerIn: parent
      color: root.background
      borderSpec: root.borderSpec
      opacity: root.opened ? 1 : 0
      scale: root.opened ? 1 : 0.96
      Behavior on opacity { NumberAnimation { duration: root.motionMs } }
      Behavior on scale { NumberAnimation { duration: root.motionMs } }

      Item {
        id: keyCatcher
        anchors.fill: parent
        focus: true
        Keys.priority: Keys.BeforeItem
        Keys.onPressed: function(event) {
          if (event.key === Qt.Key_Escape) {
            root.doDismiss()
            event.accepted = true
          } else if (root.mode !== "alarm") {
            return
          } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            root.doRedact()
            event.accepted = true
          } else if (event.key === Qt.Key_R) {
            if (Protocol.canRestore(root.incidentSrc)) {
              root.doRestore()
              event.accepted = true
            }
          } else if (event.key === Qt.Key_A) {
            root.doAllow()
            event.accepted = true
          }
        }
      }

      Flickable {
        id: scroller
        anchors.fill: parent
        anchors.margins: Style.spacing.panelPadding
        contentWidth: width
        contentHeight: pillCol.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height

      Column {
        id: pillCol
        width: scroller.width
        spacing: Style.space(10)

        Row {
          spacing: Style.space(10)
          Rectangle {
            width: Style.space(12)
            height: Style.space(12)
            radius: width / 2
            color: root.incidentTier === 1 ? root.danger : root.warning
            anchors.verticalCenter: parent.verticalCenter
          }
          Text {
            text: "Secret Canary"
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: true
            opacity: 0.7
            anchors.verticalCenter: parent.verticalCenter
          }
          Text {
            text: root.incidentTier === 1 ? "TIER 1" : "TIER 2"
            color: root.incidentTier === 1 ? root.danger : root.warning
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: true
            anchors.verticalCenter: parent.verticalCenter
          }
        }

        Text {
          width: parent.width
          text: root.mode === "settings" ? "Canary settings" : (root.incidentTitle || "Credential escaped")
          color: root.foreground
          wrapMode: Text.WordWrap
          font.family: root.fontFamily
          font.pixelSize: Style.font.heading
          font.bold: true
        }

        Text {
          width: parent.width
          visible: root.mode === "alarm"
          text: {
            var bits = []
            if (root.incidentSrc)
              bits.push(root.incidentSrc)
            if (root.incidentRule)
              bits.push(root.incidentRule)
            if (root.incidentPreview)
              bits.push(root.incidentPreview)
            if (root.incidentFile)
              bits.push(root.incidentFile)
            return bits.join("  ·  ")
          }
          color: root.foreground
          opacity: 0.72
          wrapMode: Text.WordWrap
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
        }

        Text {
          width: parent.width
          visible: root.resultLabel.length > 0
          text: root.resultLabel
          color: root.accent
          wrapMode: Text.WordWrap
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
        }

        Text {
          width: parent.width
          visible: root.incidentNote.length > 0
          text: root.incidentNote
          color: root.warning
          wrapMode: Text.WordWrap
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
        }

        Text {
          width: parent.width
          visible: root.mode === "alarm"
          text: root.keymap
          color: root.foreground
          opacity: 0.62
          wrapMode: Text.WordWrap
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }

        Row {
          spacing: Style.space(8)
          visible: root.mode === "alarm"

          Rectangle {
            width: enterLabel.implicitWidth + Style.space(20)
            height: Style.space(32)
            radius: Style.spacing.labelGap
            color: root.danger
            Text {
              id: enterLabel
              anchors.centerIn: parent
              text: root.incidentSrc === "git" ? "Enter · unstage" : "Enter · redact"
              color: "#fff"
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              font.bold: true
            }
            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: root.doRedact()
            }
          }

          Rectangle {
            visible: Protocol.canRestore(root.incidentSrc)
            width: rLabel.implicitWidth + Style.space(20)
            height: Style.space(32)
            radius: Style.spacing.labelGap
            color: Style.normalFillFor(root.foreground, root.accent)
            Text {
              id: rLabel
              anchors.centerIn: parent
              text: "R · restore"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: root.doRestore()
            }
          }

          Rectangle {
            width: aLabel.implicitWidth + Style.space(20)
            height: Style.space(32)
            radius: Style.spacing.labelGap
            color: Style.normalFillFor(root.foreground, root.accent)
            Text {
              id: aLabel
              anchors.centerIn: parent
              text: "A · allowlist"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: root.doAllow()
            }
          }
        }

        Text {
          width: parent.width
          visible: root.mode === "settings"
          text: root.statusLine + (root.muted ? "  ·  muted" : "") + "  ·  allowlist " + root.allowCount
          color: root.foreground
          opacity: 0.7
          wrapMode: Text.WordWrap
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
        }

        Rectangle {
          visible: root.mode === "settings"
          width: parent.width
          height: Style.space(36)
          radius: Style.spacing.labelGap
          color: root.danger
          Text {
            anchors.centerIn: parent
            text: "Test the canary"
            color: "#fff"
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            font.bold: true
          }
          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: root.callService("testCanary", "")
          }
        }

        Row {
          visible: root.mode === "settings"
          spacing: Style.space(8)
          Rectangle {
            width: muteSetLbl.implicitWidth + Style.space(20)
            height: Style.space(32)
            radius: Style.spacing.labelGap
            color: Style.normalFillFor(root.foreground, root.accent)
            Text {
              id: muteSetLbl
              anchors.centerIn: parent
              text: root.muted ? "Unmute" : "Mute 1 h"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            MouseArea {
              anchors.fill: parent
              onClicked: root.callService(root.muted ? "unmute" : "mute", "")
            }
          }
        }

        Text {
          visible: root.mode === "settings"
          text: "Rules — tap to disable / enable. Disabled rules stay quiet."
          color: root.foreground
          opacity: 0.7
          wrapMode: Text.WordWrap
          width: parent.width
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }

        Repeater {
          model: root.mode === "settings" ? root.ruleCatalog : []
          delegate: Row {
            spacing: Style.space(8)
            width: pillCol.width
            Text {
              text: modelData.title + (modelData.tier === 2 ? " (t2)" : "")
              color: root.foreground
              elide: Text.ElideRight
              width: parent.width - Style.space(90)
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
            Rectangle {
              width: toggleLbl.implicitWidth + Style.space(12)
              height: Style.space(22)
              radius: Style.spacing.labelGap
              color: root.ruleIsDisabled(modelData.id) ? Style.normalFillFor(root.foreground, root.accent) : root.accent
              Text {
                id: toggleLbl
                anchors.centerIn: parent
                text: root.ruleIsDisabled(modelData.id) ? "off" : "on"
                color: root.ruleIsDisabled(modelData.id) ? root.foreground : "#111"
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }
              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: root.toggleRule(modelData.id)
              }
            }
          }
        }

        Text {
          visible: root.mode === "settings"
          text: "Watched repos (" + root.repos.length + "/64) — clipboard-only until you add one"
          color: root.foreground
          opacity: 0.7
          wrapMode: Text.WordWrap
          width: parent.width
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }

        Repeater {
          model: root.mode === "settings" ? root.repos : []
          delegate: Row {
            spacing: Style.space(8)
            width: pillCol.width
            Text {
              text: modelData
              color: root.foreground
              elide: Text.ElideMiddle
              width: parent.width - Style.space(40)
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
            Text {
              text: "remove"
              color: root.danger
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              MouseArea {
                anchors.fill: parent
                onClicked: root.callService("unwatchRepo", modelData)
              }
            }
          }
        }

        Row {
          visible: root.mode === "settings"
          spacing: Style.space(8)
          width: parent.width
          Rectangle {
            width: parent.width - Style.space(64)
            height: Style.space(32)
            radius: Style.spacing.labelGap
            color: Style.normalFillFor(root.foreground, root.accent)
            TextInput {
              id: repoField
              anchors.fill: parent
              anchors.margins: 8
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              text: root.repoDraft
              onTextChanged: root.repoDraft = text
              Keys.onReturnPressed: {
                if (root.repoDraft.length)
                  root.callService("watchRepo", root.repoDraft)
                root.repoDraft = ""
                text = ""
              }
            }
          }
          Rectangle {
            width: Style.space(56)
            height: Style.space(32)
            radius: Style.spacing.labelGap
            color: root.accent
            Text {
              anchors.centerIn: parent
              text: "Add"
              color: "#111"
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              font.bold: true
            }
            MouseArea {
              anchors.fill: parent
              onClicked: {
                if (root.repoDraft.length)
                  root.callService("watchRepo", root.repoDraft)
                root.repoDraft = ""
                repoField.text = ""
              }
            }
          }
        }
      }
      }
    }
  }
}
