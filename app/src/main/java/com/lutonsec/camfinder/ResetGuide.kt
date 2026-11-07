package com.lutonsec.camfinder

/** Physical-reset reference per brand/series: button location, exact steps, factory defaults. */
class ResetInfo(
    val brand: String,
    val defaultIp: String,
    val defaultLogin: String,
    val button: String,
    val steps: List<String>,
    val noButton: String = ""
)

/**
 * Physical factory-reset procedures, matched by brand (and OEM family). Consistent within a brand/series,
 * not per exact model number — the model's label tells you the exact button spot.
 * Sources: manufacturer support pages and reset references.
 */
object ResetGuide {

    fun forBrand(brand: String?, model: String?): ResetInfo {
        val b = (brand ?: "").trim().lowercase()
        val m = (model ?: "").lowercase()

        if (b.contains("hikvision") || b == "lts" || b == "hilook")
            return ResetInfo(
                "Hikvision (and Hik-OEM: LTS, HiLook)",
                "192.168.1.64", "admin — set/activate a new password on first login",
                "Recessed RESET button: inside the housing on domes/turrets (open the cover), on the pigtail on some bullets, or on the board near the microSD slot.",
                listOf(
                    "Power the camera and let it finish booting.",
                    "Press and hold RESET about 10-20 seconds until it reboots — this defaults most models.",
                    "If it won't take, use Hikvision's full method: hold RESET for 90 seconds total;",
                    "   at the 30s mark unplug the network cable (keep holding), reconnect it at ~60s,",
                    "   keep holding to 90s, then release. The camera returns to the un-activated state.",
                    "Reconnect, find it again, and set a new admin password."
                ),
                "No button at all is rare on Hikvision; if so, default it from the NVR's camera menu."
            )

        if (b.contains("dahua") || b.contains("honeywell") || b.contains("amcrest") ||
            b.contains("lorex") || b.contains("loryta") || m.startsWith("hc3")) {
            val brandName = when {
                b.contains("honeywell") -> "Honeywell 30/35 (Dahua-OEM)"
                b.contains("amcrest") -> "Amcrest (Dahua-OEM)"
                b.contains("lorex") -> "Lorex (Dahua-OEM)"
                else -> "Dahua (and OEM: Amcrest, Lorex, Honeywell 30/35)"
            }
            return ResetInfo(
                brandName,
                "192.168.1.108  (Honeywell/Lorex: check the label — some ship DHCP)",
                "admin — newer models set the password at first setup",
                "RESET button by form factor:\n" +
                    "   - Box camera: on the back panel, marked RESET.\n" +
                    "   - Bullet with bracket: on the reset WIRE of the pigtail.\n" +
                    "   - Mini-bullet / dome / eyeball: INSIDE — open the cap/dome (eyeball: under the IR board).\n" +
                    "   - Old IR box (HFW3300/3110): no button — short the BLUE (reset) and ORANGE (gnd) pigtail wires.",
                listOf(
                    "Power the camera (12V DC or PoE).",
                    "Press and hold RESET at least 10 seconds until the camera restarts.",
                    "The PWR light (or IR block) blinks off and on — that's the reset.",
                    "Reconnect, find it again, and set a new admin password."
                ),
                "Old IR box models: short the blue + orange pigtail wires for ~10s instead of a button."
            )
        }

        if (b.contains("axis"))
            return ResetInfo(
                "Axis", "DHCP; falls back to 192.168.0.90", "set the root/admin password on first login",
                "The CONTROL button on the camera body/board.",
                listOf(
                    "Disconnect power (or pull the PoE/network cable).",
                    "Press and HOLD the Control button, and while holding it, reconnect power.",
                    "Keep holding until the Status LED turns AMBER (up to 15 seconds), then release.",
                    "Wait for the Status LED to turn GREEN (up to ~1 minute) — reset done.",
                    "Reconnect and set the IP / root password."
                )
            )

        if (b.contains("hanwha") || b.contains("wisenet") || b.contains("samsung") || b.contains("techwin"))
            return ResetInfo(
                "Hanwha (Wisenet / Samsung Techwin)",
                "DHCP; falls back to 192.168.1.100", "set credentials at first login",
                "Recessed RESET button (blue or white), usually on the board / under a cover.",
                listOf(
                    "Power the camera and let it finish booting (do NOT press during boot).",
                    "With it running, press and hold RESET for 5 seconds, then release.",
                    "The camera reboots itself to factory defaults.",
                    "Open its IP in a browser and set new credentials."
                )
            )

        if (b.contains("uniview") || b == "unv" || b.contains("univision"))
            return ResetInfo(
                "Uniview (UNV)", "192.168.1.13", "admin / 123456  (newer models set password at setup)",
                "RESET button inside the housing, or on the pigtail (open the dome/cap to reach it).",
                listOf(
                    "Power the camera and let it boot.",
                    "Press and hold RESET about 15 seconds, until the camera reboots.",
                    "Reconnect, find it again, and log in with admin / 123456 (or set a new password)."
                ),
                "No button: default it from the Uniview NVR's camera menu, or EZStation."
            )

        if (b.contains("milesight"))
            return ResetInfo(
                "Milesight", "DHCP; falls back to 192.168.5.190", "admin / ms1234",
                "RESET button on the board / pigtail.",
                listOf(
                    "Power the camera and let it boot.",
                    "Press and hold RESET until it reboots (about 5-10 seconds).",
                    "Reconnect (your device on 192.168.5.x if no DHCP) and log in admin / ms1234."
                )
            )

        if (b.contains("ubiquiti") || b.contains("unifi"))
            return ResetInfo(
                "Ubiquiti (UniFi Protect)", "DHCP", "adopted in the UniFi Protect app",
                "Recessed RESET button on the camera body/pigtail.",
                listOf(
                    "With the camera powered, press and hold RESET about 10 seconds.",
                    "The LEDs cycle and it reboots to factory defaults.",
                    "Re-adopt it in UniFi Protect."
                )
            )

        if (b.contains("reolink"))
            return ResetInfo(
                "Reolink", "DHCP", "admin — set/blank password depending on model",
                "Pinhole RESET on the body or pigtail (use a paperclip).",
                listOf(
                    "With the camera powered, press and hold the pinhole RESET about 10 seconds.",
                    "It reboots to factory defaults.",
                    "Re-add it in the Reolink app / find its new IP."
                )
            )

        if (b.contains("vivotek"))
            return ResetInfo(
                "Vivotek", "DHCP (older models 169.254.x link-local)", "root — set password on first login",
                "RESTORE button on the board (distinct from RESET, which only reboots).",
                listOf(
                    "With the camera powered, press and hold RESTORE a few seconds until it reboots.",
                    "Use Vivotek's Shepherd / IW2 tool or DHCP to find its new IP."
                )
            )

        if (b.contains("bosch"))
            return ResetInfo(
                "Bosch", "DHCP (link-local 169.254.x if none)", "set service password on first login",
                "Many Bosch models have NO reset button — they default from the web UI / Configuration Manager.",
                listOf(
                    "Preferred: log in (or use Bosch Configuration Manager) -> default from the menu.",
                    "If the model has a hardware default button, hold it ~10 seconds while powered.",
                    "Find it again with Configuration Manager or DHCP."
                ),
                "Bosch commonly resets via Configuration Manager rather than a button."
            )

        if (b.contains("avigilon"))
            return ResetInfo(
                "Avigilon", "DHCP / link-local (zero-config)", "set on first connection in ACC / web",
                "Firmware-revert / reset button on the camera body.",
                listOf(
                    "Press and hold the reset button while applying power, keep holding until it reboots.",
                    "Re-discover it in ACC or via DHCP."
                )
            )

        if (b.contains("xiongmai") || b == "xm")
            return ResetInfo(
                "Xiongmai / generic OEM (Sofia)", "192.168.1.10 (or DHCP)", "admin / (blank)",
                "Often NO button — many reset only from the NVR/DVR menu or a tiny board pad.",
                listOf(
                    "If there's a button/pad: hold it ~10 seconds while powered.",
                    "Otherwise reset from the recorder's camera menu or the XMEye / DeviceManager tool.",
                    "Default login is admin with a blank password."
                ),
                "Reset from the NVR camera menu or XMEye if there's no button."
            )

        return ResetInfo(
            if (brand.isNullOrEmpty()) "Unknown — check the label" else brand,
            "check the camera's label / quick guide (often 192.168.1.x or DHCP)",
            "admin — set/confirm password on first login",
            "Recessed RESET button: on the pigtail, under a rubber cover, inside the dome/bullet, or near the SD-card slot.",
            listOf(
                "Power the camera and let it boot.",
                "Press and hold RESET about 10-20 seconds, until the camera reboots.",
                "Reconnect, find it again, and set a new admin password.",
                "If there's no button, the camera may only reset from its NVR's camera menu."
            ),
            "Some OEM cameras reset only from the NVR/recorder menu."
        )
    }

    fun physicalBlock(brand: String?, model: String?): String {
        val r = forBrand(brand, model)
        val sb = StringBuilder()
        sb.append("PHYSICAL RESET  —  ").append(r.brand).append('\n')
        sb.append("Button:  ").append(r.button).append('\n')
        sb.append("Steps:\n")
        for (s in r.steps) sb.append(if (s.startsWith("   ")) s else "- $s").append('\n')
        sb.append("After reset  ->  default IP: ").append(r.defaultIp).append('\n')
        sb.append("             login: ").append(r.defaultLogin).append('\n')
        return sb.toString()
    }
}
