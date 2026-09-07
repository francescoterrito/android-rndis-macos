// AndroidRNDIS menu bar app: status + connection stats + auto-connect toggle.
// Polls /tmp/android-rndis-macos-status.json (written by the root daemon) and
// toggles /tmp/android-rndis-macos.disabled (read by --watch). No privileges here.
import Cocoa

let statusPath = "/tmp/android-rndis-macos-status.json"
let disableFlagPath = "/tmp/android-rndis-macos.disabled"

func fmtBytes(_ n: Double) -> String {
    if n < 1024 { return String(format: "%.0f B", n) }
    if n < 1024 * 1024 { return String(format: "%.1f KB", n / 1024) }
    if n < 1024 * 1024 * 1024 { return String(format: "%.1f MB", n / 1024 / 1024) }
    return String(format: "%.2f GB", n / 1024 / 1024 / 1024)
}

func fmtDur(_ s: Double) -> String {
    let t = Int(s)
    if t < 60 { return "\(t)s" }
    if t < 3600 { return "\(t / 60)m \(t % 60)s" }
    return "\(t / 3600)h \((t % 3600) / 60)m"
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var item: NSStatusItem!
    var statusLine: NSMenuItem!
    var ipLine: NSMenuItem!
    var statsLine: NSMenuItem!
    var speedLine: NSMenuItem!
    var toggleItem: NSMenuItem!
    var lastRx: Double = -1
    var lastTx: Double = -1
    var lastAt: Date?
    var lastSession = ""
    var starting = false
    var startupError: String?

    func applicationDidFinishLaunching(_ note: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "○ tether"
        let menu = NSMenu()
        statusLine = NSMenuItem(title: "Status: —", action: nil, keyEquivalent: "")
        statusLine.isEnabled = false
        ipLine = NSMenuItem(title: "IP: —", action: nil, keyEquivalent: "")
        ipLine.isEnabled = false
        statsLine = NSMenuItem(title: "Session: —", action: nil, keyEquivalent: "")
        statsLine.isEnabled = false
        speedLine = NSMenuItem(title: "Speed: —", action: nil, keyEquivalent: "")
        speedLine.isEnabled = false
        toggleItem = NSMenuItem(title: "Auto-connect", action: #selector(toggle), keyEquivalent: "")
        toggleItem.target = self
        let quit = NSMenuItem(title: "Turn off & Quit", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self
        menu.addItem(statusLine)
        menu.addItem(ipLine)
        menu.addItem(statsLine)
        menu.addItem(speedLine)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(toggleItem)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(quit)
        item.menu = menu
        Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            self?.refresh()
        }
        refresh()
    }

    var autoOn: Bool {
        !FileManager.default.fileExists(atPath: disableFlagPath)
    }

    func statusFileExists() -> Bool {
        FileManager.default.fileExists(atPath: statusPath)
    }

    func daemonKnownInstalled() -> Bool {
        FileManager.default.fileExists(
            atPath: "/Library/LaunchDaemons/com.android-rndis-macos.plist")
    }

    func showError(_ message: String) {
        startupError = message
        let alert = NSAlert()
        alert.messageText = "Could not start USB tethering"
        alert.informativeText = message
        alert.runModal()
    }

    @objc func toggle() {
        guard !starting else { return }
        if autoOn && daemonActive() {
            guard FileManager.default.createFile(atPath: disableFlagPath, contents: nil) else {
                showError("Could not write the stop request.")
                return
            }
        } else {
            ensureDaemon()
        }
        refresh()
    }

    func daemonActive() -> Bool {
        guard statusFresh(),
              let data = try? Data(contentsOf: URL(fileURLWithPath: statusPath)),
              let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let state = j["state"] as? String,
              let pid = (j["pid"] as? NSNumber)?.int32Value,
              pid > 1, state != "off", kill(pid, 0) == 0 || errno == EPERM
        else { return false }
        return true
    }

    func ensureDaemon() {
        guard !starting else { return }
        guard daemonKnownInstalled(), FileManager.default.isExecutableFile(
            atPath: "/usr/local/bin/android-rndis-macos") else {
            showError("The tethering service is missing. Install it with sudo make install from the project folder.")
            return
        }
        starting = true
        startupError = nil
        refresh()
        DispatchQueue.global().async {
            // bootstrap only loads a service. kickstart also handles a job
            // which is already loaded but exited cleanly after Turn off.
            let command = "/bin/rm -f /tmp/android-rndis-macos.disabled && " +
                "(/bin/launchctl print system/com.android-rndis-macos.daemon >/dev/null 2>&1 || " +
                "/bin/launchctl bootstrap system /Library/LaunchDaemons/com.android-rndis-macos.plist) && " +
                "/bin/launchctl kickstart -k system/com.android-rndis-macos.daemon"
            let script = "do shell script \"" + command + "\" with administrator privileges"
            let p = Process()
            let errors = Pipe()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            p.arguments = ["-e", script]
            p.standardError = errors
            var failure: String?
            do {
                try p.run()
                let data = errors.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                if p.terminationStatus != 0 {
                    failure = String(data: data, encoding: .utf8) ?? "Service startup failed."
                }
            } catch { failure = error.localizedDescription }
            let result = failure
            DispatchQueue.main.async {
                self.starting = false
                if let result = result { self.showError(result) }
                self.refresh()
            }
        }
    }

    func statusFresh() -> Bool {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: statusPath),
              let mtime = attrs[.modificationDate] as? Date
        else { return false }
        let age = Date().timeIntervalSince(mtime)
        return age >= 0 && age < 20
    }

    @objc func quitApp() {
        // Total quit: disable auto-connect so the daemon tears its session
        // down, restores the network and exits by itself (~1s), then exit.
        // Nothing of ours keeps running: no process, no utun, no routes.
        guard !starting else { return }
        guard FileManager.default.createFile(atPath: disableFlagPath, contents: nil) else {
            showError("Could not write the stop request; the app is staying open.")
            return
        }
        NSApplication.shared.terminate(nil)
    }

    func refresh() {
        toggleItem.isEnabled = !starting
        let active = daemonActive()
        toggleItem.title = starting ? "Starting…" : (active && autoOn ? "Turn off" : "Turn on")
        toggleItem.state = active && autoOn ? .on : .off
        if starting {
            item.button?.title = "◌ tether"
            statusLine.title = "Status: starting…"
            return
        }
        if let error = startupError {
            statusLine.title = "Status: " + error.components(separatedBy: .newlines).first!
            return
        }
        guard active,
              let data = try? Data(contentsOf: URL(fileURLWithPath: statusPath)),
              let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            item.button?.title = "○ tether"
            if !daemonKnownInstalled() {
                statusLine.title = "Status: daemon not installed (sudo make install)"
            } else if !statusFileExists() {
                statusLine.title = "Status: off"
            } else {
                statusLine.title = "Status: daemon stopped"
            }
            ipLine.title = "IP: —"
            statsLine.title = "Session: —"
            speedLine.title = "Speed: —"
            lastRx = -1
            return
        }
        let state = j["state"] as? String ?? "?"
        let ip = j["ip"] as? String ?? ""
        let rx = (j["rx_bytes"] as? NSNumber)?.doubleValue ?? 0
        let tx = (j["tx_bytes"] as? NSNumber)?.doubleValue ?? 0
        let up = (j["uptime_sec"] as? NSNumber)?.doubleValue ?? 0
        let session = "\(j["pid"] ?? "")/\(j["ifname"] ?? "")"
        if session != lastSession || rx < lastRx || tx < lastTx { lastRx = -1 }
        lastSession = session
        let now = Date()
        var rate = ""
        if lastRx >= 0, let at = lastAt {
            let dt = now.timeIntervalSince(at)
            if dt > 0 {
                rate = "↓ \(fmtBytes((rx - lastRx) / dt))/s ↑ \(fmtBytes((tx - lastTx) / dt))/s"
            }
        }
        lastRx = rx
        lastTx = tx
        lastAt = now
        let dot = state == "connected" ? "●" : "○"
        item.button?.title = "\(dot) \(fmtBytes(rx))"
        statusLine.title = "Status: \(state)\(autoOn ? "" : " (auto-connect off)")"
        ipLine.title = ip.isEmpty ? "IP: —" : "IP: \(ip)"
        statsLine.title = "Session: ↓ \(fmtBytes(rx)) ↑ \(fmtBytes(tx)) · \(fmtDur(up))"
        speedLine.title = rate.isEmpty ? "Speed: measuring…" : "Speed: \(rate)"
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
