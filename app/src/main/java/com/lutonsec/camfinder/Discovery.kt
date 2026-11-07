package com.lutonsec.camfinder

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.nio.charset.StandardCharsets

/**
 * Active multi-protocol discovery: ONVIF WS-Discovery, Hikvision SADP, Dahua DHIP + DVRIP, Xiongmai/Sofia.
 * The probes are multicast/broadcast at layer 2, so cameras reply even when their IP is in a different range
 * than the tester — that's how an "unreachable" camera on the switch still shows up.
 *
 * The Activity must hold a WifiManager.MulticastLock while this runs (so Wi-Fi delivers broadcast/multicast).
 */
object Discovery {
    private const val MCAST_WS = "239.255.255.250"      // ONVIF 3702, SADP 37020
    private const val MCAST_DAHUA = "239.255.255.251"   // DHIP 37810

    // ---- probe builders ----
    fun buildOnvifProbe(): ByteArray {
        val id = "uuid:" + java.util.UUID.randomUUID()
        val xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" " +
            "xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
            "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" " +
            "xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">" +
            "<e:Header><w:MessageID>$id</w:MessageID>" +
            "<w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>" +
            "<w:Action e:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>" +
            "</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>"
        return xml.toByteArray(StandardCharsets.UTF_8)
    }

    fun buildSadpProbe(): ByteArray =
        ("<?xml version=\"1.0\" encoding=\"utf-8\"?><Probe><Uuid>" +
            java.util.UUID.randomUUID().toString().uppercase() +
            "</Uuid><Types>inquiry</Types></Probe>").toByteArray(StandardCharsets.UTF_8)

    fun buildDahuaDhipProbe(): ByteArray {
        val json = "{\"method\":\"DHDiscover.search\",\"params\":{\"mac\":\"\",\"uni\":1}}"
        val body = json.toByteArray(StandardCharsets.US_ASCII)
        val hdr = ByteArray(32)
        hdr[0] = 0x20; hdr[4] = 'D'.code.toByte(); hdr[5] = 'H'.code.toByte(); hdr[6] = 'I'.code.toByte(); hdr[7] = 'P'.code.toByte()
        putU32LE(hdr, 16, body.size); putU32LE(hdr, 24, body.size)
        return hdr + body
    }

    fun buildDahuaDvripProbe(): ByteArray {
        val p = ByteArray(32); p[0] = 0xA3.toByte(); p[1] = 0x01; p[16] = 0x02; return p
    }

    fun buildXiongmaiProbe(): ByteArray {
        val p = ByteArray(20); p[0] = 0xFF.toByte(); p[14] = 0xFA.toByte(); p[15] = 0x05; return p
    }

    private fun putU32LE(b: ByteArray, off: Int, v: Int) {
        b[off] = (v and 0xFF).toByte(); b[off + 1] = ((v ushr 8) and 0xFF).toByte()
        b[off + 2] = ((v ushr 16) and 0xFF).toByte(); b[off + 3] = ((v ushr 24) and 0xFF).toByte()
    }

    // ---- scan engine ----
    fun scanAll(nics: List<LocalNic>, seconds: Int, onFound: (Device) -> Unit, log: (String) -> Unit) {
        val deadline = System.currentTimeMillis() + seconds * 1000L
        val sockets = ArrayList<DatagramSocket>()
        val threads = ArrayList<Thread>()

        fun spawnReader(s: DatagramSocket) {
            val t = Thread {
                val buf = ByteArray(65535)
                try { s.soTimeout = 500 } catch (_: Exception) {}
                while (System.currentTimeMillis() < deadline) {
                    try {
                        val pkt = DatagramPacket(buf, buf.size)
                        s.receive(pkt)
                        if (pkt.length <= 0) continue
                        val data = buf.copyOf(pkt.length)
                        val d = parseDatagram(data, pkt.address?.hostAddress ?: "")
                        if (d != null && d.ip.isNotEmpty()) onFound(d)
                    } catch (_: java.net.SocketTimeoutException) {
                    } catch (_: Exception) {}
                }
            }
            t.isDaemon = true; threads.add(t); t.start()
        }

        // Fixed-port listeners (catch replies to the well-known port / multicast group).
        val sadp = makeMulticast(37020, MCAST_WS, nics, log)
        val dhip = makeMulticast(37810, MCAST_DAHUA, nics, log)
        val dvrip = makeBroadcast(5050, log)
        val xm = makeBroadcast(34569, log)
        for (s in listOf(sadp, dhip, dvrip, xm)) if (s != null) { sockets.add(s); spawnReader(s) }

        // Per-NIC ephemeral sender/receiver (ONVIF + unicast replies to the source port).
        val senders = ArrayList<DatagramSocket>()
        for (nic in nics) {
            try {
                val s = DatagramSocket(null)
                s.reuseAddress = true
                s.broadcast = true
                s.bind(InetSocketAddress(nic.ip, 0))
                senders.add(s); sockets.add(s); spawnReader(s)
            } catch (e: Exception) { log("sender bind ${nic.ip.hostAddress}: ${e.message}") }
        }

        val onvif = buildOnvifProbe(); val sadpP = buildSadpProbe()
        val dhipP = buildDahuaDhipProbe(); val dvripP = buildDahuaDvripProbe(); val xmP = buildXiongmaiProbe()

        fun send(s: DatagramSocket?, data: ByteArray, ip: String, port: Int) {
            if (s == null) return
            try { s.send(DatagramPacket(data, data.size, InetAddress.getByName(ip), port)) } catch (_: Exception) {}
        }

        fun burst() {
            for (nic in nics) {
                val bc = NetUtil.broadcast(nic)
                for (s in senders) {
                    send(s, onvif, MCAST_WS, 3702)
                    send(s, sadpP, MCAST_WS, 37020)
                    send(s, dhipP, MCAST_DAHUA, 37810)
                    send(s, dhipP, "255.255.255.255", 37810)
                    send(s, dhipP, bc, 37810)
                    send(s, dvripP, "255.255.255.255", 5050)
                    send(s, dvripP, bc, 5050)
                    send(s, xmP, "255.255.255.255", 34569)
                    send(s, xmP, bc, 34569)
                }
            }
            send(sadp, sadpP, MCAST_WS, 37020)
            send(dhip, dhipP, MCAST_DAHUA, 37810)
            send(dhip, dhipP, "255.255.255.255", 37810)
        }

        log("sending probes on ${nics.size} interface(s)...")
        burst()
        try { Thread.sleep(minOf(1500L, seconds * 500L)) } catch (_: Exception) {}
        if (System.currentTimeMillis() < deadline) burst()

        for (t in threads) try { t.join(seconds * 1000L + 1000L) } catch (_: Exception) {}
        for (s in sockets) try { s.close() } catch (_: Exception) {}
    }

    private fun makeMulticast(port: Int, group: String, nics: List<LocalNic>, log: (String) -> Unit): DatagramSocket? {
        return try {
            val s = MulticastSocket(port)
            s.reuseAddress = true
            try { s.broadcast = true } catch (_: Exception) {}
            val g = InetAddress.getByName(group)
            for (nic in nics) {
                try {
                    val ni = NetworkInterface.getByName(nic.name)
                    @Suppress("DEPRECATION")
                    if (ni != null) s.joinGroup(InetSocketAddress(g, port), ni) else s.joinGroup(g)
                } catch (_: Exception) {}
            }
            s
        } catch (e: Exception) { log("bind :$port failed (${e.message})"); null }
    }

    private fun makeBroadcast(port: Int, log: (String) -> Unit): DatagramSocket? {
        return try {
            val s = DatagramSocket(null); s.reuseAddress = true; s.broadcast = true
            s.bind(InetSocketAddress(port)); s
        } catch (e: Exception) { log("bind :$port failed (${e.message})"); null }
    }

    // ---- datagram parsing (auto-detect by content) ----
    fun parseDatagram(data: ByteArray, fromIp: String): Device? {
        try {
            if (data.isNotEmpty() && (data[0] == '<'.code.toByte() || looksText(data))) {
                val xml = String(data, StandardCharsets.UTF_8)
                if (xml.contains("XAddrs", true) || xml.contains("ProbeMatches", true)) return parseOnvif(xml, fromIp)
                if (xml.contains("IPv4Address", true)) return parseSadp(xml, fromIp)
            }
            if (data.size > 32 && data[4] == 'D'.code.toByte() && data[5] == 'H'.code.toByte() &&
                data[6] == 'I'.code.toByte() && data[7] == 'P'.code.toByte()) return parseDahuaJson(data, fromIp)
            if (data.size > 137 && data[0] == 0xB3.toByte()) return parseDvrip(data, fromIp)
            if (data.size > 20 && ((data[14].toInt() and 0xFF) or ((data[15].toInt() and 0xFF) shl 8)) == 1531)
                return parseXiongmai(data, fromIp)
            if (data.size > 8 && data.indexOf('{'.code.toByte()) >= 0) {
                val js = String(data, StandardCharsets.UTF_8)
                if (js.contains("IPAddress") || js.contains("\"mac\"")) return parseDahuaJson(data, fromIp)
            }
        } catch (_: Exception) {}
        return null
    }

    private fun looksText(d: ByteArray): Boolean {
        val lim = minOf(d.size, 8)
        for (i in 0 until lim) {
            val b = d[i].toInt() and 0xFF
            if (b != 9 && b != 10 && b != 13 && (b < 32 || b > 126)) return false
        }
        return true
    }

    private fun parseOnvif(xml: String, fromIp: String): Device {
        val d = Device(); d.source = "ONVIF"
        val m = Regex("https?://([0-9]{1,3}(?:\\.[0-9]{1,3}){3})(?::(\\d+))?/").find(xml)
        if (m != null) {
            d.ip = m.groupValues[1]
            val full = Regex("https?://[^\\s<]+/onvif/device_service").find(xml)
            d.onvifXAddr = full?.value ?: m.value.trimEnd('/')
        } else d.ip = fromIp
        Regex("onvif://www\\.onvif\\.org/name/([^\\s<]+)").find(xml)?.let { d.name = decodeScope(it.groupValues[1]) }
        Regex("onvif://www\\.onvif\\.org/hardware/([^\\s<]+)").find(xml)?.let { d.model = decodeScope(it.groupValues[1]) }
        return d
    }

    private fun decodeScope(s: String): String =
        try { java.net.URLDecoder.decode(s, "UTF-8").replace('_', ' ').trim() } catch (_: Exception) { s }

    private fun parseSadp(xml: String, fromIp: String): Device {
        val d = Device(); d.source = "SADP"
        d.ip = tag(xml, "IPv4Address").ifEmpty { fromIp }
        d.mac = normMac(tag(xml, "MAC"))
        d.model = first(tag(xml, "DeviceType"), tag(xml, "DeviceDescription"))
        d.serial = first(tag(xml, "SerialNO"), tag(xml, "DeviceSN"))
        d.mask = tag(xml, "IPv4SubnetMask"); d.gateway = tag(xml, "IPv4Gateway")
        tag(xml, "HttpPort").toIntOrNull()?.let { if (it > 0) d.httpPort = it }
        if (tag(xml, "Activated").trim().equals("false", true)) d.activated = false
        return d
    }

    private fun parseDahuaJson(data: ByteArray, fromIp: String): Device? {
        val brace = data.indexOf('{'.code.toByte()); if (brace < 0) return null
        val js = String(data, brace, data.size - brace, StandardCharsets.UTF_8)
        val d = Device(); d.source = "Dahua"
        d.ip = first(jsonStr(js, "IPAddress"), jsonStr(js, "IPv4Address")).ifEmpty { fromIp }
        d.mac = normMac(first(jsonStr(js, "mac"), jsonStr(js, "MAC")))
        d.model = first(jsonStr(js, "deviceType"), jsonStr(js, "DeviceType"))
        d.serial = first(jsonStr(js, "serialNo"), jsonStr(js, "SerialNo"))
        d.mask = first(jsonStr(js, "SubnetMask"), jsonStr(js, "IPv4SubnetMask"))
        d.gateway = first(jsonStr(js, "DefaultGateway"), jsonStr(js, "Gateway"))
        return d
    }

    private fun parseDvrip(data: ByteArray, fromIp: String): Device {
        val d = Device(); d.source = "DVRIP"
        try {
            d.ip = "${data[56].toInt() and 0xFF}.${data[57].toInt() and 0xFF}.${data[58].toInt() and 0xFF}.${data[59].toInt() and 0xFF}"
            d.mac = normMac(String(data, 120, 17, StandardCharsets.US_ASCII))
            val modelLen = minOf(32, data.size - 137)
            if (modelLen > 0) d.model = String(data, 137, modelLen, StandardCharsets.US_ASCII).replace("\u0000", "").trim()
            d.name = String(data, 32, 16, StandardCharsets.US_ASCII).replace("\u0000", "").trim()
        } catch (_: Exception) {}
        if (d.ip.isEmpty() || d.ip == "0.0.0.0") d.ip = fromIp
        return d
    }

    private fun parseXiongmai(data: ByteArray, fromIp: String): Device {
        var len = (data[16].toInt() and 0xFF) or ((data[17].toInt() and 0xFF) shl 8) or
                ((data[18].toInt() and 0xFF) shl 16) or ((data[19].toInt() and 0xFF) shl 24)
        if (len <= 0 || 20 + len > data.size) len = data.size - 20
        val js = String(data, 20, len, StandardCharsets.UTF_8).replace("\u0000", "")
        val d = Device(); d.source = "Xiongmai"; d.brand = "Xiongmai"
        d.mac = normMac(jsonStr(js, "MAC"))
        d.ip = hexToIp(jsonStr(js, "HostIP")).ifEmpty { fromIp }
        d.mask = hexToIp(jsonStr(js, "Submask")); d.gateway = hexToIp(jsonStr(js, "GateWay"))
        d.name = jsonStr(js, "HostName")
        return d
    }

    // ---- helpers ----
    private fun tag(xml: String, name: String): String =
        Regex("<$name>(.*?)</$name>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
            .find(xml)?.groupValues?.get(1)?.trim() ?: ""

    private fun jsonStr(js: String, key: String): String =
        Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"", RegexOption.IGNORE_CASE).find(js)?.groupValues?.get(1)?.trim() ?: ""

    private fun hexToIp(hexIn: String): String {
        if (hexIn.isEmpty()) return ""
        var hex = hexIn.trim(); if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2)
        val v = hex.toLongOrNull(16) ?: return ""
        return "${v and 0xFF}.${(v shr 8) and 0xFF}.${(v shr 16) and 0xFF}.${(v shr 24) and 0xFF}"
    }

    private fun normMac(mac: String?): String {
        if (mac.isNullOrEmpty()) return ""
        val sb = StringBuilder()
        for (c in mac) if (c.isDigit() || c in 'a'..'f' || c in 'A'..'F') sb.append(c.uppercaseChar())
        if (sb.length < 12) return ""
        val out = StringBuilder()
        var i = 0
        while (i < 12) { if (i > 0) out.append(':'); out.append(sb[i]); out.append(sb[i + 1]); i += 2 }
        return out.toString()
    }

    private fun first(vararg vals: String): String { for (v in vals) if (v.isNotEmpty()) return v; return "" }
}
