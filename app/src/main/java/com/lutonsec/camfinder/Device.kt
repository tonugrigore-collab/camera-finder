package com.lutonsec.camfinder

/** One discovered device on the wire. */
class Device {
    var ip = ""
    var mac = ""
    var vendor = ""      // full IEEE name
    var brand = ""       // short brand for the list
    var model = ""
    var name = ""
    var serial = ""
    var httpPort = 80
    var mask = ""
    var gateway = ""
    var onvifXAddr = ""
    var activated = true // Hikvision: false = needs activation
    var source = ""      // ONVIF / SADP / Dahua / DVRIP / Xiongmai / ARP
    var type = ""        // Camera / Printer / Switch-Router / PC / NAS — from fingerprinting

    val key: String
        get() = if (mac.isNotEmpty()) "M:" + mac.uppercase() else "I:$ip"

    fun mergeFrom(o: Device) {
        if (ip.isEmpty()) ip = o.ip
        if (mac.isEmpty()) mac = o.mac
        if (model.isEmpty()) model = o.model
        if (name.isEmpty()) name = o.name
        if (serial.isEmpty()) serial = o.serial
        if (mask.isEmpty()) mask = o.mask
        if (gateway.isEmpty()) gateway = o.gateway
        if (onvifXAddr.isEmpty()) onvifXAddr = o.onvifXAddr
        if (!o.activated) activated = false
        if (o.source.isNotEmpty() && (source.isEmpty() || !source.contains(o.source)))
            source = if (source.isEmpty()) o.source else "$source+${o.source}"
        if (brand.isEmpty()) brand = o.brand
        if (type.isEmpty()) type = o.type
    }

    fun fillVendorFromMac() {
        if (mac.isNotEmpty()) {
            vendor = Oui.vendor(mac)
            val sb = Oui.shortBrand(vendor)
            if (sb.isNotEmpty()) brand = sb        // OUI brand is authoritative when we have the MAC
        }
        if (brand.isEmpty()) brand = guessBrand()  // off-subnet (no MAC): fall back to protocol/model
    }

    private fun guessBrand(): String {
        val m = model.uppercase()
        if (m.startsWith("HC3")) return "Honeywell"
        if (m.startsWith("DS-")) return "Hikvision"
        return when {
            source.contains("SADP") -> "Hikvision"
            source.contains("Dahua") || source.contains("DVRIP") -> "Dahua"
            source.contains("Xiongmai") -> "Xiongmai"
            else -> ""
        }
    }
}
