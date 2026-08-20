import QtQuick
import Quickshell

// Isolates shell-injection and Quickshell APIs we are not 100% sure of.
// See ASSUMPTIONS.md.

Item {
  id: adapter

  readonly property string pluginId: "io.github.chris.secret-canary"

  function pluginDirFrom(manifest, fallbackUrl) {
    if (manifest && manifest.__sourceDir)
      return String(manifest.__sourceDir).replace(/\/$/, "")
    var u = String(fallbackUrl || "")
    if (u.indexOf("file://") === 0)
      u = u.slice(7)
    if (u.length > 1 && u.charAt(u.length - 1) === "/")
      u = u.slice(0, u.length - 1)
    return u
  }

  function env(name) {
    try {
      return Quickshell.env(name) || ""
    } catch (e) {
      return ""
    }
  }

  function findService(shell, pluginRegistry, bar) {
    var sh = shell || (bar && bar.shell) || null
    if (pluginRegistry && typeof pluginRegistry.serviceFor === "function") {
      var a = pluginRegistry.serviceFor(pluginId)
      if (a)
        return a
    }
    if (sh && typeof sh.serviceFor === "function") {
      var b = sh.serviceFor(pluginId)
      if (b)
        return b
    }
    if (sh && typeof sh.firstPartyServiceFor === "function") {
      var c = sh.firstPartyServiceFor(pluginId)
      if (c)
        return c
    }
    return null
  }

  function summon(shell, payload) {
    var body = payload || "{}"
    try {
      Quickshell.execDetached(["omarchy-shell", "shell", "summon", pluginId, body])
      return true
    } catch (e) {
      return false
    }
  }

  function hide(shell) {
    try {
      Quickshell.execDetached(["omarchy-shell", "shell", "hide", pluginId])
      return true
    } catch (e) {
      return false
    }
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

  function callIpc(shell, method, arg) {
    var verb = adapter.ipcVerb(method)
    try {
      var cmd = ["omarchy-shell", "shell", "call", pluginId, verb]
      if (arg !== undefined && arg !== null && String(arg).length)
        cmd.push(String(arg))
      Quickshell.execDetached(cmd)
      return true
    } catch (e) {
      return false
    }
  }

  function writeDaemon(proc, line) {
    try {
      if (proc && typeof proc.write === "function") {
        var r = proc.write(String(line) + "\n")
        if (r === false || r === 0)
          return false
        return true
      }
    } catch (e) {}
    return false
  }

  function dangerColor(Color) {
    try { if (Color && Color.danger) return Color.danger } catch (e) {}
    try { if (Color && Color.error) return Color.error } catch (e2) {}
    try { if (Color && Color.menu && Color.menu.danger) return Color.menu.danger } catch (e3) {}
    return "#cc4444"
  }

  function warningColor(Color) {
    try { if (Color && Color.warning) return Color.warning } catch (e) {}
    try { if (Color && Color.amber) return Color.amber } catch (e2) {}
    try { if (Color && Color.menu && Color.menu.warning) return Color.menu.warning } catch (e3) {}
    return "#d4a017"
  }

  function okColor(Color) {
    try { if (Color && Color.success) return Color.success } catch (e) {}
    try { if (Color && Color.good) return Color.good } catch (e2) {}
    return "#3d8b5c"
  }

  function reduceMotion(Style) {
    try {
      if (Style && Style.reduceMotion)
        return true
    } catch (e) {}
    try {
      if (env("OMARCHY_REDUCED_MOTION") === "1")
        return true
    } catch (e2) {}
    return false
  }

  function chime() {
    try {
      Quickshell.execDetached(["paplay", "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"])
    } catch (e) {}
  }
}
