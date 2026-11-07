package com.lutonsec.camfinder

import android.content.Context
import java.util.zip.GZIPInputStream

/**
 * IEEE OUI (MAC prefix) -> manufacturer lookup. This names every brand in the world from a camera's MAC,
 * even one that answers no discovery protocol. Data ships as assets/oui.tsv.gz ("PREFIX\tVendor"), which is
 * the public IEEE registry data — refresh it any time from https://standards-oui.ieee.org/ for a sellable build.
 */
object Oui {
    private val map = HashMap<String, String>(40000)
    @Volatile private var loaded = false

    fun ensureLoaded(ctx: Context) {
        if (loaded) return
        synchronized(this) {
            if (loaded) return
            try {
                ctx.assets.open("oui.tsv.gz").use { raw ->
                    GZIPInputStream(raw).bufferedReader().useLines { lines ->
                        for (line in lines) {
                            val tab = line.indexOf('\t')
                            if (tab == 6) {
                                val prefix = line.substring(0, 6).uppercase()
                                val vendor = line.substring(tab + 1).trim()
                                if (vendor.isNotEmpty()) map.putIfAbsent(prefix, vendor)
                            }
                        }
                    }
                }
            } catch (_: Exception) { /* lookups return "" */ }
            loaded = true
        }
    }

    fun vendor(mac: String?): String {
        if (mac.isNullOrEmpty()) return ""
        val sb = StringBuilder(6)
        for (c in mac) {
            if (c.isDigit() || c in 'a'..'f' || c in 'A'..'F') sb.append(c.uppercaseChar())
            if (sb.length == 6) break
        }
        if (sb.length < 6) return ""
        return map[sb.toString()] ?: ""
    }

    /** Collapse the long IEEE name into a short, friendly brand word for the list. */
    fun shortBrand(vendor: String?): String {
        if (vendor.isNullOrEmpty()) return ""
        val v = vendor.lowercase()
        return when {
            v.contains("hikvision") -> "Hikvision"
            v.contains("dahua") -> "Dahua"
            v.contains("axis") -> "Axis"
            v.contains("hanwha") || v.contains("samsung tech") || v.contains("techwin") -> "Hanwha"
            v.contains("uniview") || v.contains("univision") -> "Uniview"
            v.contains("honeywell") -> "Honeywell"
            v.contains("avigilon") -> "Avigilon"
            v.contains("vivotek") -> "Vivotek"
            v.contains("milesight") -> "Milesight"
            v.contains("ubiquiti") -> "Ubiquiti"
            v.contains("bosch") -> "Bosch"
            v.contains("pelco") -> "Pelco"
            v.contains("reolink") -> "Reolink"
            v.contains("amcrest") -> "Amcrest"
            v.contains("xiongmai") -> "Xiongmai"
            v.contains("tp-link") || v.contains("tplink") -> "TP-Link"
            v.contains("lorex") -> "Lorex"
            else -> vendor.split(' ', ',', '.').firstOrNull { it.isNotEmpty() } ?: vendor
        }
    }
}
