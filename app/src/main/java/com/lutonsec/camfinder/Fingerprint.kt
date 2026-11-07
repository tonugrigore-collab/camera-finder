package com.lutonsec.camfinder

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Works out what a device IS (camera / printer / switch / PC / NAS) from which TCP ports answer plus an
 * SNMP sysDescr read. Mirrors the Windows version so both apps classify devices the same way.
 */
object Fingerprint {
    private val tcpPorts = intArrayOf(80, 443, 554, 8000, 37777, 34567, 8899, 9100, 631, 515, 22, 445, 139, 3389, 23, 8080, 21, 5000)

    class Result { val open = HashSet<Int>(); var snmp = "" }

    fun probe(ip: String): Result {
        val res = Result()
        val lock = Any()
        val threads = ArrayList<Thread>()
        for (port in tcpPorts) {
            val p = port
            val t = Thread { if (tcpOpen(ip, p, 250)) synchronized(lock) { res.open.add(p) } }
            t.isDaemon = true; threads.add(t); t.start()
        }
        for (t in threads) try { t.join(700) } catch (_: Exception) {}
        res.snmp = Snmp.sysDescr(ip, 300)
        return res
    }

    private fun tcpOpen(ip: String, port: Int, timeout: Int): Boolean =
        try { Socket().use { it.connect(InetSocketAddress(ip, port), timeout); true } } catch (_: Exception) { false }

    fun inferType(d: Device, r: Result) {
        val o = r.open
        val vendor = d.vendor.lowercase()
        val snmp = r.snmp
        val s = snmp.lowercase()
        val cameraProto = d.source.contains("ONVIF") || d.source.contains("SADP") ||
                d.source.contains("Dahua") || d.source.contains("DVRIP") || d.source.contains("Xiongmai")

        d.type = when {
            cameraProto || 554 in o || 8000 in o || 37777 in o || 34567 in o || 8899 in o -> "Camera"
            9100 in o || 631 in o || 515 in o || s.contains("jetdirect") || s.contains("laserjet") || s.contains("printer") -> "Printer"
            s.contains("switch") || s.contains("router") || s.contains("cisco") || s.contains("mikrotik") ||
                s.contains("ubiquiti") || s.contains("juniper") || s.contains("aruba") || s.contains("procurve") ||
                s.contains("netgear") || s.contains("fortinet") || s.contains("edgeos") || s.contains("routeros") -> "Switch/Router"
            445 in o || 3389 in o || 139 in o -> "Windows PC"
            22 in o || 5000 in o -> "Linux/NAS"
            snmp.isNotEmpty() -> "Network device"
            isPrinterVendor(vendor) -> "Printer"
            isNetVendor(vendor) -> "Switch/Router"
            80 in o || 443 in o || 8080 in o -> "Web device"
            o.isNotEmpty() -> "Host"
            else -> "?"
        }
        if (d.model.isEmpty() && snmp.isNotEmpty()) d.model = trunc(snmp, 48)
    }

    private fun isPrinterVendor(v: String) =
        listOf("brother", "lexmark", "kyocera", "ricoh", "epson", "canon", "xerox", "zebra").any { v.contains(it) }

    private fun isNetVendor(v: String) =
        listOf("cisco", "ubiquiti", "netgear", "aruba", "juniper", "mikrotik", "fortinet", "zyxel", "ruckus", "extreme", "d-link", "tp-link").any { v.contains(it) }

    private fun trunc(s: String, n: Int): String {
        val t = s.replace("\r", " ").replace("\n", " ").trim()
        return if (t.length <= n) t else t.substring(0, n) + "…"
    }
}

/** Minimal SNMP v1 GET of sysDescr (1.3.6.1.2.1.1.1.0), community "public". Names switches/printers/routers. */
object Snmp {
    fun sysDescr(ip: String, timeout: Int): String {
        return try {
            val oid = bytes(0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00)
            val req = buildGet("public", oid)
            DatagramSocket().use { u ->
                u.soTimeout = timeout
                u.send(DatagramPacket(req, req.size, InetAddress.getByName(ip), 161))
                val buf = ByteArray(2048)
                val resp = DatagramPacket(buf, buf.size)
                u.receive(resp)
                parseValueAfterOid(buf.copyOf(resp.length), oid)
            }
        } catch (_: Exception) { "" }
    }

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    private fun tlv(tag: Int, v: ByteArray): ByteArray {
        val b = ByteArray(v.size + 2); b[0] = tag.toByte(); b[1] = v.size.toByte()
        System.arraycopy(v, 0, b, 2, v.size); return b
    }

    private fun cat(vararg parts: ByteArray): ByteArray {
        var n = 0; for (p in parts) n += p.size
        val b = ByteArray(n); var o = 0
        for (p in parts) { System.arraycopy(p, 0, b, o, p.size); o += p.size }
        return b
    }

    private fun buildGet(community: String, oid: ByteArray): ByteArray {
        val varbind = tlv(0x30, cat(tlv(0x06, oid), tlv(0x05, ByteArray(0))))
        val vbl = tlv(0x30, varbind)
        val reqid = bytes(0x12, 0x34, 0x56, 0x78)
        val pdu = tlv(0xA0, cat(tlv(0x02, reqid), tlv(0x02, bytes(0)), tlv(0x02, bytes(0)), vbl))
        val comm = tlv(0x04, community.toByteArray(Charsets.US_ASCII))
        val ver = tlv(0x02, bytes(0))
        return tlv(0x30, cat(ver, comm, pdu))
    }

    private fun parseValueAfterOid(resp: ByteArray, oid: ByteArray): String {
        var i = 0
        while (i + 2 + oid.size < resp.size) {
            if ((resp[i].toInt() and 0xFF) == 0x06 && (resp[i + 1].toInt() and 0xFF) == oid.size) {
                var match = true
                for (j in oid.indices) if (resp[i + 2 + j] != oid[j]) { match = false; break }
                if (match) {
                    val vi = i + 2 + oid.size
                    if (vi + 1 >= resp.size) return ""
                    val vtag = resp[vi].toInt() and 0xFF
                    val li = vi + 1
                    var len = resp[li].toInt() and 0xFF
                    var di = li + 1
                    if (len and 0x80 != 0) {
                        val nb = len and 0x7f; len = 0; var k = 0
                        while (k < nb && di < resp.size) { len = (len shl 8) or (resp[di].toInt() and 0xFF); di++; k++ }
                    }
                    if (di + len > resp.size) len = resp.size - di
                    return if (vtag == 0x04) String(resp, di, len, Charsets.UTF_8) else ""
                }
            }
            i++
        }
        return ""
    }
}
