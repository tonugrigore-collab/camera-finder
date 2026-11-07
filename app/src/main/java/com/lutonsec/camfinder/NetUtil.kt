package com.lutonsec.camfinder

import java.net.InetAddress
import java.net.NetworkInterface

/** A usable local IPv4 interface (eth0 on a tester's RJ45, or wlan0). */
class LocalNic(
    val name: String,          // eth0 / wlan0  (needed for the root temp-IP command)
    val display: String,
    val ip: InetAddress,
    val prefix: Int,
    val mac: String
) {
    val ipInt: Int get() = NetUtil.ipToInt(ip)
    override fun toString() = display
}

object NetUtil {

    fun ipToInt(ip: InetAddress): Int {
        val b = ip.address
        return ((b[0].toInt() and 0xFF) shl 24) or ((b[1].toInt() and 0xFF) shl 16) or
                ((b[2].toInt() and 0xFF) shl 8) or (b[3].toInt() and 0xFF)
    }

    fun ipToInt(s: String): Int = ipToInt(InetAddress.getByName(s))

    fun intToIp(v: Int): String =
        "${(v ushr 24) and 0xFF}.${(v ushr 16) and 0xFF}.${(v ushr 8) and 0xFF}.${v and 0xFF}"

    fun maskFromPrefix(p: Int): Int = when {
        p <= 0 -> 0
        p >= 32 -> -1
        else -> (-1) shl (32 - p)
    }

    fun maskStringFromPrefix(p: Int): String = intToIp(maskFromPrefix(p))

    fun prefixFromMask(maskStr: String): Int =
        try { Integer.bitCount(ipToInt(maskStr)) } catch (_: Exception) { 24 }

    fun sameSubnet(aIp: Int, bIp: Int, prefix: Int): Boolean {
        val m = maskFromPrefix(prefix)
        return (aIp and m) == (bIp and m)
    }

    fun sameSubnet(nic: LocalNic, ip: String): Boolean =
        try { sameSubnet(nic.ipInt, ipToInt(ip), nic.prefix) } catch (_: Exception) { false }

    fun broadcast(nic: LocalNic): String {
        val m = maskFromPrefix(nic.prefix)
        val bcast = (nic.ipInt and m) or m.inv()
        return intToIp(bcast)
    }

    /** Usable host IPs in a subnet (skips network + broadcast), capped so a wide mask can't spin forever. */
    fun subnetHosts(ipInt: Int, prefix: Int, cap: Int = 1024): List<String> {
        val m = maskFromPrefix(prefix)
        val net = ipInt and m
        var count = (m.inv().toLong() and 0xFFFFFFFFL)   // addresses - 1
        if (count > cap) count = cap.toLong()
        val out = ArrayList<String>(count.toInt().coerceAtLeast(0))
        var i = 1L
        while (i < count) { out.add(intToIp((net.toLong() + i).toInt())); i++ }
        return out
    }

    fun localNics(): List<LocalNic> {
        val list = ArrayList<LocalNic>()
        try {
            for (ni in NetworkInterface.getNetworkInterfaces()) {
                if (!ni.isUp || ni.isLoopback) continue
                val macBytes = try { ni.hardwareAddress } catch (_: Exception) { null }
                val mac = if (macBytes != null && macBytes.size >= 6)
                    macBytes.take(6).joinToString(":") { String.format("%02X", it) } else ""
                for (ia in ni.interfaceAddresses) {
                    val a = ia.address ?: continue
                    if (a.address.size != 4) continue            // IPv4 only
                    if (a.isLoopbackAddress || a.isLinkLocalAddress) continue
                    val prefix = ia.networkPrefixLength.toInt().let { if (it in 1..32) it else 24 }
                    list.add(LocalNic(ni.name, "${ni.name}  [${a.hostAddress}]", a, prefix, mac))
                }
            }
        } catch (_: Exception) { }
        return list
    }
}
