package com.lutonsec.camfinder

import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Root helpers for a camera tester (handheld testers are rooted). Used for two things a stock Android
 * can't do: add a temporary IP to reach an off-subnet camera, and read the ARP table. Everything degrades
 * gracefully when root isn't available.
 */
object Root {
    @Volatile private var suChecked = false
    @Volatile private var suAvailable = false

    fun hasSu(): Boolean {
        if (suChecked) return suAvailable
        suAvailable = try {
            val p = ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
            val out = BufferedReader(InputStreamReader(p.inputStream)).readText()
            p.waitFor()
            out.contains("uid=0") || out.contains("root")
        } catch (_: Exception) { false }
        suChecked = true
        return suAvailable
    }

    /** Run a command as root. Returns combined output, or null if root isn't available. */
    fun run(cmd: String): String? {
        if (!hasSu()) return null
        return try {
            val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start()
            val out = BufferedReader(InputStreamReader(p.inputStream)).readText()
            p.waitFor()
            out
        } catch (_: Exception) { null }
    }

    fun addTempIp(iface: String, ip: String, prefix: Int): Boolean {
        val r = run("ip addr add $ip/$prefix dev $iface")
        return r != null && !r.contains("Operation not permitted", true)
    }

    fun delTempIp(iface: String, ip: String, prefix: Int) { run("ip addr del $ip/$prefix dev $iface") }

    /** /proc/net/arp contents (tries plain read first, then root). May be empty on locked-down non-root devices. */
    fun readArp(): String {
        try { val f = File("/proc/net/arp"); if (f.canRead()) { val t = f.readText(); if (t.lines().size > 1) return t } } catch (_: Exception) {}
        return run("cat /proc/net/arp") ?: ""
    }
}
