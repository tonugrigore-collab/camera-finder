package com.lutonsec.camfinder

import android.util.Base64
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

class OpResult(val ok: Boolean, val message: String) {
    companion object {
        fun good(m: String) = OpResult(true, m)
        fun bad(m: String) = OpResult(false, m)
    }
}

/** HTTP with Basic/Digest auth (Android's HttpURLConnection does not do Digest itself). */
object Http {
    private val rnd = SecureRandom()

    private val trustAll: javax.net.ssl.SSLSocketFactory by lazy {
        val tm = object : X509TrustManager {
            override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
            override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
            override fun getAcceptedIssuers() = arrayOf<java.security.cert.X509Certificate>()
        }
        val ctx = SSLContext.getInstance("TLS"); ctx.init(null, arrayOf(tm), SecureRandom())
        ctx.socketFactory
    }

    private class Resp(val code: Int, val text: String, val authHeader: String?)

    private fun request(method: String, urlStr: String, authorization: String?,
                        body: ByteArray?, contentType: String?, timeout: Int): Resp {
        val c = URL(urlStr).openConnection() as HttpURLConnection
        if (c is HttpsURLConnection) { c.sslSocketFactory = trustAll; c.hostnameVerifier = HostnameVerifier { _, _ -> true } }
        c.connectTimeout = timeout; c.readTimeout = timeout; c.useCaches = false
        c.requestMethod = method
        c.setRequestProperty("User-Agent", "CameraFinder")
        if (authorization != null) c.setRequestProperty("Authorization", authorization)
        if (body != null) {
            c.doOutput = true
            c.setRequestProperty("Content-Type", contentType ?: "text/xml; charset=utf-8")
            c.setFixedLengthStreamingMode(body.size)
            c.outputStream.use { it.write(body) }
        }
        val code = try { c.responseCode } catch (_: Exception) { -1 }
        val stream = if (code in 200..399) c.inputStream else c.errorStream
        val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
        val auth = c.getHeaderField("WWW-Authenticate")
        c.disconnect()
        return Resp(code, text, auth)
    }

    /** Returns (httpStatus, responseText). Handles a 401 Digest/Basic challenge with one retry. */
    fun send(method: String, urlStr: String, user: String, pass: String,
             body: ByteArray?, contentType: String?, timeout: Int): Pair<Int, String> {
        var r = request(method, urlStr, null, body, contentType, timeout)
        if (r.code != 401 || user.isEmpty()) return r.code to r.text
        val wa = r.authHeader ?: return r.code to r.text
        val auth = when {
            wa.startsWith("Digest", true) -> buildDigest(method, urlStr, user, pass, wa)
            wa.startsWith("Basic", true) -> "Basic " + Base64.encodeToString("$user:$pass".toByteArray(), Base64.NO_WRAP)
            else -> null
        } ?: return r.code to r.text
        r = request(method, urlStr, auth, body, contentType, timeout)
        return r.code to r.text
    }

    private fun buildDigest(method: String, urlStr: String, user: String, pass: String, challenge: String): String {
        fun field(k: String) = Regex("$k\\s*=\\s*\"?([^\",]+)\"?", RegexOption.IGNORE_CASE).find(challenge)?.groupValues?.get(1) ?: ""
        val realm = field("realm"); val nonce = field("nonce"); val qop = field("qop"); val opaque = field("opaque")
        val u = URL(urlStr); val uri = u.file.ifEmpty { "/" }
        val ha1 = md5("$user:$realm:$pass"); val ha2 = md5("$method:$uri")
        val sb = StringBuilder("Digest username=\"$user\", realm=\"$realm\", nonce=\"$nonce\", uri=\"$uri\"")
        if (qop.isNotEmpty()) {
            val nc = "00000001"; val cnonce = randHex(8)
            val resp = md5("$ha1:$nonce:$nc:$cnonce:auth:$ha2")
            sb.append(", qop=auth, nc=$nc, cnonce=\"$cnonce\", response=\"$resp\"")
        } else {
            sb.append(", response=\"${md5("$ha1:$nonce:$ha2")}\"")
        }
        if (opaque.isNotEmpty()) sb.append(", opaque=\"$opaque\"")
        sb.append(", algorithm=MD5")
        return sb.toString()
    }

    fun md5(s: String): String =
        MessageDigest.getInstance("MD5").digest(s.toByteArray(Charsets.ISO_8859_1)).joinToString("") { "%02x".format(it) }

    fun sha1Base64(data: ByteArray): String =
        Base64.encodeToString(MessageDigest.getInstance("SHA-1").digest(data), Base64.NO_WRAP)

    fun randBytes(n: Int): ByteArray { val b = ByteArray(n); rnd.nextBytes(b); return b }
    private fun randHex(n: Int): String { val b = randBytes(n); return b.joinToString("") { "%02x".format(it) } }
    fun base64(b: ByteArray): String = Base64.encodeToString(b, Base64.NO_WRAP)
}

/** ONVIF over SOAP with WS-Security UsernameToken digest — the universal path for all ONVIF brands. */
object Onvif {
    private fun serviceUrl(d: Device) = if (d.onvifXAddr.isNotEmpty()) d.onvifXAddr else "http://${d.ip}/onvif/device_service"

    private fun header(user: String, pass: String): String {
        if (user.isEmpty()) return ""
        val nonce = Http.randBytes(16)
        val created = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", java.util.Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }.format(java.util.Date())
        val createdB = created.toByteArray(Charsets.UTF_8)
        val passB = pass.toByteArray(Charsets.UTF_8)
        val digest = Http.sha1Base64(nonce + createdB + passB)
        return "<s:Header><Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">" +
            "<UsernameToken><Username>${esc(user)}</Username>" +
            "<Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">$digest</Password>" +
            "<Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">${Http.base64(nonce)}</Nonce>" +
            "<Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">$created</Created>" +
            "</UsernameToken></Security></s:Header>"
    }

    private fun envelope(user: String, pass: String, body: String): String =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope " +
            "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" " +
            "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" " +
            "xmlns:tt=\"http://www.onvif.org/ver10/schema\">" + header(user, pass) + "<s:Body>$body</s:Body></s:Envelope>"

    private fun call(d: Device, user: String, pass: String, body: String): Pair<Int, String> =
        Http.send("POST", serviceUrl(d), "", "", envelope(user, pass, body).toByteArray(Charsets.UTF_8),
            "application/soap+xml; charset=utf-8", 8000)

    fun getInfo(d: Device, user: String, pass: String): OpResult {
        return try {
            val (st, r) = call(d, user, pass, "<tds:GetDeviceInformation/>")
            if (st == 200) {
                d.model = first(tag(r, "Model"), d.model); d.serial = first(tag(r, "SerialNumber"), d.serial)
                OpResult.good("${tag(r, "Manufacturer")} ${d.model} (fw ${tag(r, "FirmwareVersion")})")
            } else OpResult.bad(fault(r, st))
        } catch (e: Exception) { OpResult.bad(e.message ?: "error") }
    }

    fun setIp(d: Device, user: String, pass: String, ip: String, mask: String, gw: String): OpResult {
        return try {
            var (st, r) = call(d, user, pass, "<tds:GetNetworkInterfaces/>")
            var token = Regex("token=\"([^\"]+)\"").find(r)?.groupValues?.get(1) ?: "eth0"
            val prefix = NetUtil.prefixFromMask(mask)
            val set = "<tds:SetNetworkInterfaces><tds:InterfaceToken>${esc(token)}</tds:InterfaceToken>" +
                "<tds:NetworkInterface><tt:Enabled>true</tt:Enabled><tt:IPv4><tt:Enabled>true</tt:Enabled>" +
                "<tt:Manual><tt:Address>${esc(ip)}</tt:Address><tt:PrefixLength>$prefix</tt:PrefixLength></tt:Manual>" +
                "<tt:DHCP>false</tt:DHCP></tt:IPv4></tds:NetworkInterface></tds:SetNetworkInterfaces>"
            val res = call(d, user, pass, set); st = res.first; r = res.second
            if (st != 200) return OpResult.bad("Set IP failed: ${fault(r, st)}")
            if (gw.isNotEmpty()) call(d, user, pass, "<tds:SetNetworkDefaultGateway><tds:IPv4Address>${esc(gw)}</tds:IPv4Address></tds:SetNetworkDefaultGateway>")
            OpResult.good("IP set to $ip/$prefix via ONVIF. The camera may reboot to apply.")
        } catch (e: Exception) { OpResult.bad(e.message ?: "error") }
    }

    fun factoryReset(d: Device, user: String, pass: String, hard: Boolean): OpResult {
        return try {
            val (st, r) = call(d, user, pass, "<tds:SetSystemFactoryDefault><tds:FactoryDefault>${if (hard) "Hard" else "Soft"}</tds:FactoryDefault></tds:SetSystemFactoryDefault>")
            if (st == 200) OpResult.good("Factory reset sent (${if (hard) "hard" else "soft"}). Camera is resetting.") else OpResult.bad(fault(r, st))
        } catch (e: Exception) { OpResult.bad(e.message ?: "error") }
    }

    fun reboot(d: Device, user: String, pass: String): OpResult {
        return try {
            val (st, r) = call(d, user, pass, "<tds:SystemReboot/>")
            if (st == 200) OpResult.good("Reboot sent.") else OpResult.bad(fault(r, st))
        } catch (e: Exception) { OpResult.bad(e.message ?: "error") }
    }

    private fun fault(xml: String, st: Int): String {
        val reason = first(tag(xml, "Text"), tag(xml, "faultstring"))
        return if (reason.isEmpty()) "HTTP $st" else reason
    }
    private fun tag(xml: String, local: String): String =
        Regex("<(?:\\w+:)?$local[^>]*>(.*?)</(?:\\w+:)?$local>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
            .find(xml)?.groupValues?.get(1)?.trim() ?: ""
    private fun first(vararg v: String): String { for (x in v) if (x.isNotEmpty()) return x; return "" }
    private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
}

/** Hikvision (and Hik-OEM) native ISAPI path over HTTP digest. */
object Hik {
    fun setIp(d: Device, user: String, pass: String, ip: String, mask: String, gw: String): OpResult {
        return try {
            val body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<IPAddress xmlns=\"http://www.hikvision.com/ver20/XMLSchema\" version=\"2.0\">" +
                "<ipVersion>v4</ipVersion><addressingType>static</addressingType>" +
                "<ipAddress>$ip</ipAddress><subnetMask>$mask</subnetMask>" +
                "<DefaultGateway><ipAddress>${if (gw.isEmpty()) ip else gw}</ipAddress></DefaultGateway></IPAddress>"
            val (st, r) = Http.send("PUT", url(d, "/ISAPI/System/Network/interfaces/1/ipAddress"), user, pass,
                body.toByteArray(Charsets.UTF_8), "application/xml", 8000)
            if (st == 200) OpResult.good("IP set to $ip via Hikvision ISAPI.") else OpResult.bad("ISAPI set IP: HTTP $st ${tag(r, "statusString")}")
        } catch (e: Exception) { OpResult.bad(e.message ?: "error") }
    }

    fun factoryReset(d: Device, user: String, pass: String, full: Boolean): OpResult {
        return try {
            val (st, r) = Http.send("PUT", url(d, "/ISAPI/System/factoryReset?mode=${if (full) "full" else "basic"}"),
                user, pass, ByteArray(0), "application/xml", 8000)
            if (st == 200) OpResult.good("Factory reset (${if (full) "full" else "basic"}) sent.") else OpResult.bad("HTTP $st ${tag(r, "statusString")}")
        } catch (e: Exception) { OpResult.bad(e.message ?: "error") }
    }

    fun reboot(d: Device, user: String, pass: String): OpResult {
        return try {
            val (st, _) = Http.send("PUT", url(d, "/ISAPI/System/reboot"), user, pass, ByteArray(0), "application/xml", 8000)
            if (st == 200) OpResult.good("Reboot sent.") else OpResult.bad("HTTP $st")
        } catch (e: Exception) { OpResult.bad(e.message ?: "error") }
    }

    private fun url(d: Device, path: String): String {
        val port = if (d.httpPort > 0) d.httpPort else 80
        val scheme = if (port == 443) "https" else "http"
        val host = if (port == 80 || port == 443) d.ip else "${d.ip}:$port"
        return "$scheme://$host$path"
    }
    private fun tag(xml: String, local: String): String =
        Regex("<(?:\\w+:)?$local[^>]*>(.*?)</(?:\\w+:)?$local>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
            .find(xml)?.groupValues?.get(1)?.trim() ?: ""
}
