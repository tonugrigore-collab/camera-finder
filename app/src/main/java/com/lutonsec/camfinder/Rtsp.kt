package com.lutonsec.camfinder

import java.net.URLEncoder

/** Candidate RTSP URLs per brand, Main or Sub stream. ExoPlayer plays one; on error we cycle to the next. */
object Rtsp {
    fun urls(ip: String, brand: String, user: String, pass: String, sub: Boolean): List<String> {
        val cred = if (user.isEmpty()) ""
        else URLEncoder.encode(user, "UTF-8") + ":" + URLEncoder.encode(pass, "UTF-8") + "@"
        val pre = "rtsp://$cred$ip:554"
        val b = brand.lowercase()
        val dahua = listOf("dahua", "honeywell", "amcrest", "lorex", "alerton", "uniview").any { b.contains(it) }
        val hik = "/Streaming/Channels/10" + (if (sub) "2" else "1")
        val dh = "/cam/realmonitor?channel=1&subtype=" + (if (sub) "1" else "0")
        val out = LinkedHashSet<String>()
        if (b.contains("hikvision")) out.add(pre + hik)
        if (dahua) out.add(pre + dh)
        if (b.contains("axis")) out.add(pre + "/axis-media/media.amp" + (if (sub) "?streamprofile=sub" else ""))
        // common / ONVIF-ish paths for any brand (requested stream first)
        out.add(pre + hik)
        out.add(pre + dh)
        out.add(pre + (if (sub) "/live/sub" else "/live"))
        out.add(pre + "/profile" + (if (sub) "2" else "1") + "/media.smp")
        out.add(pre + "/onvif" + (if (sub) "2" else "1"))
        // last resort: the other stream, so something plays
        out.add(pre + "/Streaming/Channels/10" + (if (sub) "1" else "2"))
        out.add(pre + "/cam/realmonitor?channel=1&subtype=" + (if (sub) "0" else "1"))
        return out.toList()
    }
}
