package com.lutonsec.camfinder

import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class MainActivity : AppCompatActivity() {

    private lateinit var nicSpinner: Spinner
    private lateinit var userField: EditText
    private lateinit var passField: EditText
    private lateinit var arpCheck: CheckBox
    private lateinit var findButton: Button
    private lateinit var statusLabel: TextView
    private lateinit var progress: ProgressBar
    private lateinit var deviceList: ListView

    private val devices = LinkedHashMap<String, Device>()
    private val ordered = ArrayList<Device>()
    private val localIps = HashSet<String>()
    private lateinit var adapter: DeviceAdapter
    private val lock = Any()

    private var multicastLock: WifiManager.MulticastLock? = null
    private val tempIps = ArrayList<Triple<String, String, Int>>()   // iface, ip, prefix
    @Volatile private var scanning = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        nicSpinner = findViewById(R.id.nicSpinner)
        userField = findViewById(R.id.userField)
        passField = findViewById(R.id.passField)
        arpCheck = findViewById(R.id.arpCheck)
        findButton = findViewById(R.id.findButton)
        statusLabel = findViewById(R.id.statusLabel)
        progress = findViewById(R.id.progress)
        deviceList = findViewById(R.id.deviceList)

        adapter = DeviceAdapter()
        deviceList.adapter = adapter
        deviceList.setOnItemClickListener { _, _, pos, _ -> showActions(ordered[pos]) }
        findButton.setOnClickListener { startScan() }

        Thread { Oui.ensureLoaded(applicationContext) }.start()
        populateNics()

        try {
            val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            multicastLock = wifi.createMulticastLock("camfinder").apply { setReferenceCounted(true); acquire() }
        } catch (_: Exception) {}
    }

    override fun onDestroy() {
        super.onDestroy()
        clearTempIps()
        try { multicastLock?.release() } catch (_: Exception) {}
    }

    private fun populateNics() {
        val nics = NetUtil.localNics()
        nicSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, nics)
        if (nics.isEmpty()) setStatus("No active network adapter found — connect the tester to the switch.")
    }

    private fun selectedNic(): LocalNic? = nicSpinner.selectedItem as? LocalNic
    private fun u() = userField.text.toString().trim()
    private fun p() = passField.text.toString()

    private fun setStatus(s: String) = runOnUiThread { statusLabel.text = s }

    // ---- scanning ----
    private fun startScan() {
        if (scanning) return
        val nics = (0 until nicSpinner.count).mapNotNull { nicSpinner.getItemAtPosition(it) as? LocalNic }
        if (nics.isEmpty()) { populateNics(); return }
        val sel = selectedNic()
        localIps.clear(); nics.forEach { it.ip.hostAddress?.let { ip -> localIps.add(ip) } }
        clearTempIps()
        synchronized(lock) { devices.clear(); ordered.clear() }
        runOnUiThread { adapter.notifyDataSetChanged(); progress.visibility = View.VISIBLE; findButton.isEnabled = false }
        scanning = true
        setStatus("Scanning…")

        Thread {
            try {
                Discovery.scanAll(nics, 5, { upsert(it) }, { })
                if (arpCheck.isChecked) { setStatus("ARP sweep across all subnets…"); for (nic in nics) deepSweep(nic) }
                resolveMissingMacs()
                setStatus("Identifying devices…")
                fingerprintPass()
            } catch (_: Exception) {
            } finally {
                scanning = false
                val n = synchronized(lock) { devices.size }
                runOnUiThread { progress.visibility = View.GONE; findButton.isEnabled = true }
                setStatus("Done. $n device(s) found.")
            }
        }.start()
    }

    private fun upsert(d: Device) {
        if (d.ip.isEmpty()) return
        if (localIps.contains(d.ip)) return      // skip this device (the tester) itself
        synchronized(lock) {
            val existing = devices[d.key]
            if (existing != null) existing.mergeFrom(d)
            else { devices[d.key] = d; ordered.add(d) }
            (devices[d.key] ?: d).fillVendorFromMac()
        }
        runOnUiThread { adapter.notifyDataSetChanged() }
    }

    /** Provoke ARP across the subnet, then read the ARP table to catch silent devices + fill MACs. */
    private fun deepSweep(nic: LocalNic) {
        val hosts = NetUtil.subnetHosts(nic.ipInt, nic.prefix)
        val pool = Executors.newFixedThreadPool(64)
        for (h in hosts) pool.submit {
            try { InetAddress.getByName(h).isReachable(250) } catch (_: Exception) {}
            try { Socket().use { it.connect(InetSocketAddress(h, 80), 150) } } catch (_: Exception) {}
        }
        pool.shutdown(); try { pool.awaitTermination(8, TimeUnit.SECONDS) } catch (_: Exception) {}
        for (line in Root.readArp().lines().drop(1)) {
            val cols = line.trim().split(Regex("\\s+"))
            if (cols.size >= 4) {
                val ip = cols[0]; val mac = cols[3]
                if (mac != "00:00:00:00:00:00" && mac.count { it == ':' } == 5) {
                    val d = Device().apply { this.ip = ip; this.mac = mac.uppercase(); source = "ARP" }
                    upsert(d)
                }
            }
        }
    }

    /** ONVIF hits carry no MAC; fill it from the ARP table so the vendor shows. */
    private fun resolveMissingMacs() {
        val arp = HashMap<String, String>()
        for (line in Root.readArp().lines().drop(1)) {
            val c = line.trim().split(Regex("\\s+"))
            if (c.size >= 4 && c[3].count { it == ':' } == 5) arp[c[0]] = c[3].uppercase()
        }
        val todo = synchronized(lock) { ordered.filter { it.mac.isEmpty() } }
        for (d in todo) { val mac = arp[d.ip]; if (mac != null) { d.mac = mac; d.fillVendorFromMac() } }
        runOnUiThread { adapter.notifyDataSetChanged() }
    }

    /** Identify each device (camera / printer / switch / PC / NAS) by port + SNMP fingerprinting, in parallel. */
    private fun fingerprintPass() {
        val all = synchronized(lock) { ArrayList(ordered) }
        val pool = Executors.newFixedThreadPool(16)
        for (d in all) pool.submit {
            try { val r = Fingerprint.probe(d.ip); Fingerprint.inferType(d, r) } catch (_: Exception) {}
            runOnUiThread { adapter.notifyDataSetChanged() }
        }
        pool.shutdown()
        try { pool.awaitTermination(60, TimeUnit.SECONDS) } catch (_: Exception) {}
    }

    private fun isReachable(d: Device): Boolean {
        for (i in 0 until nicSpinner.count) {
            val nic = nicSpinner.getItemAtPosition(i) as? LocalNic ?: continue
            if (NetUtil.sameSubnet(nic, d.ip)) return true
        }
        return false
    }

    // ---- actions ----
    private fun showActions(d: Device) {
        val items = arrayOf("Open in browser", "Change IP / settings", "Reset help", "Factory reset", "Reboot", "Copy IP")
        AlertDialog.Builder(this)
            .setTitle("${d.ip}   ${if (d.brand.isNotEmpty()) d.brand else d.vendor}")
            .setItems(items) { _, which ->
                when (which) {
                    0 -> openInBrowser(d)
                    1 -> changeIp(d)
                    2 -> resetHelp(d)
                    3 -> factoryReset(d)
                    4 -> reboot(d)
                    5 -> { (getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager)
                        .setPrimaryClip(android.content.ClipData.newPlainText("ip", d.ip)); setStatus("Copied ${d.ip}") }
                }
            }.show()
    }

    private fun openInBrowser(d: Device) {
        val url = (if (d.httpPort == 443) "https://" else "http://") + d.ip +
                (if (d.httpPort == 80 || d.httpPort == 443) "" else ":${d.httpPort}") + "/"
        if (isReachable(d)) { launch(url); return }
        val sel = selectedNic() ?: run { toast("Pick the adapter on the camera switch first."); return }
        val prefix = if (d.mask.isNotEmpty()) NetUtil.prefixFromMask(d.mask) else 24
        val temp = pickTemp(d.ip, prefix)
        if (!Root.hasSu()) {
            toast("Camera ${d.ip} is on a different range. Root is needed to add a temporary IP, or set the tester's IP to ${temp}/$prefix manually.")
            return
        }
        if (Root.addTempIp(sel.name, temp, prefix)) {
            tempIps.add(Triple(sel.name, temp, prefix))
            setStatus("Added temp IP $temp on ${sel.name} to reach ${d.ip}")
            launch(url)
            toast("Temp IP $temp added so you can reach ${d.ip}. It clears on next Find or when you close the app.")
        } else toast("Could not add a temporary IP (root refused).")
    }

    private fun changeIp(d: Device) {
        val pad = dp(16)
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, 0) }
        val ip = EditText(this).apply { hint = "New IP"; setText(d.ip); inputType = InputType.TYPE_CLASS_TEXT }
        val mask = EditText(this).apply { hint = "Subnet mask"; setText(if (d.mask.isNotEmpty()) d.mask else "255.255.255.0") }
        val gw = EditText(this).apply { hint = "Gateway"; setText(d.gateway) }
        box.addView(ip); box.addView(mask); box.addView(gw)
        AlertDialog.Builder(this)
            .setTitle("Change IP — ${d.ip}")
            .setView(box)
            .setPositiveButton("Apply") { _, _ ->
                runWithReach(d, "Change IP") {
                    if (d.brand == "Hikvision") {
                        val r = Hik.setIp(d, u(), p(), ip.text.toString().trim(), mask.text.toString().trim(), gw.text.toString().trim())
                        if (r.ok) r else Onvif.setIp(d, u(), p(), ip.text.toString().trim(), mask.text.toString().trim(), gw.text.toString().trim())
                    } else Onvif.setIp(d, u(), p(), ip.text.toString().trim(), mask.text.toString().trim(), gw.text.toString().trim())
                }
            }
            .setNegativeButton("Cancel", null).show()
    }

    private fun factoryReset(d: Device) {
        val full = CheckBox(this).apply { text = "Full reset — also wipes network + admin password"; val pd = dp(16); setPadding(pd, pd, pd, 0) }
        AlertDialog.Builder(this)
            .setTitle("Factory reset — ${d.ip}")
            .setMessage("Resets the camera to factory defaults. Needs the admin login.")
            .setView(full)
            .setPositiveButton("Reset") { _, _ ->
                runWithReach(d, "Factory reset") {
                    if (d.brand == "Hikvision") { val r = Hik.factoryReset(d, u(), p(), full.isChecked); if (r.ok) r else Onvif.factoryReset(d, u(), p(), full.isChecked) }
                    else Onvif.factoryReset(d, u(), p(), full.isChecked)
                }
            }
            .setNegativeButton("Cancel", null).show()
    }

    private fun reboot(d: Device) {
        AlertDialog.Builder(this).setTitle("Reboot ${d.ip}?")
            .setPositiveButton("Reboot") { _, _ ->
                runWithReach(d, "Reboot") {
                    if (d.brand == "Hikvision") { val r = Hik.reboot(d, u(), p()); if (r.ok) r else Onvif.reboot(d, u(), p()) }
                    else Onvif.reboot(d, u(), p())
                }
            }.setNegativeButton("Cancel", null).show()
    }

    private fun resetHelp(d: Device) {
        val tv = TextView(this).apply {
            text = buildResetText(d); typeface = android.graphics.Typeface.MONOSPACE; textSize = 12f
            val pd = dp(14); setPadding(pd, pd, pd, pd); setTextIsSelectable(true)
        }
        val scroll = ScrollView(this).apply { addView(tv) }
        AlertDialog.Builder(this).setTitle("Reset help — ${d.ip}").setView(scroll)
            .setPositiveButton("Close", null)
            .setNeutralButton("Copy serial/MAC/date") { _, _ ->
                (getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager)
                    .setPrimaryClip(android.content.ClipData.newPlainText("info",
                        "IP: ${d.ip}\nMAC: ${d.mac}\nModel: ${d.model}\nSerial: ${d.serial}\nDate: ${today()}"))
            }.show()
    }

    /** Ensure reachability (temp IP if off-subnet + root), run op off the UI thread, show the result. */
    private fun runWithReach(d: Device, title: String, op: () -> OpResult) {
        if (u().isEmpty()) { toast("Enter the camera's admin user + password first."); return }
        val sel = selectedNic()
        setStatus("$title on ${d.ip}…")
        Thread {
            var temp: Triple<String, String, Int>? = null
            try {
                if (!isReachable(d) && sel != null && Root.hasSu()) {
                    val prefix = if (d.mask.isNotEmpty()) NetUtil.prefixFromMask(d.mask) else 24
                    val t = pickTemp(d.ip, prefix)
                    if (Root.addTempIp(sel.name, t, prefix)) temp = Triple(sel.name, t, prefix)
                }
                val r = op()
                runOnUiThread {
                    AlertDialog.Builder(this).setTitle(if (r.ok) "$title — done" else "$title — failed")
                        .setMessage(r.message).setPositiveButton("OK", null).show()
                }
                setStatus("$title: ${if (r.ok) "done" else "failed"}")
            } catch (e: Exception) { setStatus("$title error: ${e.message}") }
            finally { if (temp != null) Root.delTempIp(temp.first, temp.second, temp.third) }
        }.start()
    }

    private fun buildResetText(d: Device): String {
        val brand = if (d.brand.isEmpty()) "(unknown — check the label)" else d.brand
        val sb = StringBuilder()
        sb.append("Reset this camera — the physical button, and the no-password routes.\n")
        sb.append("No password cracking; these are the manufacturer-supported ways.\n")
        sb.append("=".repeat(58)).append('\n')
        sb.append("This device:\n")
        sb.append("   IP     : ${d.ip}\n   MAC    : ${d.mac}\n   Vendor : ${d.vendor}\n")
        sb.append("   Brand  : $brand\n   Model  : ${d.model}\n   Serial : ${d.serial}\n")
        sb.append("   Today  : ${today()}   (manufacturer reset codes are tied to this date)\n")
        sb.append("=".repeat(58)).append("\n\n")
        sb.append(ResetGuide.physicalBlock(brand, d.model)).append('\n')
        sb.append("(Matched to the brand/series. The exact button spot is on the\n model's own label — the form factor decides where it hides.)\n\n")
        sb.append("-".repeat(58)).append('\n')
        sb.append("LOCKED OUT (no button, or it won't default) — manufacturer reset:\n")
        when {
            brand == "Hikvision" -> {
                sb.append("  - Newer firmware: SADP -> 'Forgot Password' -> Export the file,\n")
                sb.append("    send it to your Hik dealer/support the SAME day.\n")
                sb.append("  - Older firmware: give them the Serial + today's date above.\n")
                sb.append("  - They return a reset code valid for that date; enter it in SADP.\n")
            }
            brand == "Dahua" || brand == "Honeywell" || brand == "Amcrest" || brand == "Lorex" -> {
                sb.append("  - Reset email / security questions set at activation: 'Forgot\n")
                sb.append("    password' on the login page -> temporary code -> new password.\n")
                sb.append("  - Otherwise give Dahua support the Serial + today's date for a\n")
                sb.append("    temporary password (ConfigTool shows the same serial).\n")
            }
            else -> {
                sb.append("  - Most brands reset a forgotten password from the serial + date,\n")
                sb.append("    or a reset email set at setup. Give support Serial+MAC+date.\n")
                sb.append("  - ONVIF cameras: the physical button above is the sure route.\n")
            }
        }
        return sb.toString()
    }

    // ---- helpers ----
    private fun pickTemp(cameraIp: String, prefix: Int): String {
        return try {
            val ipInt = NetUtil.ipToInt(cameraIp); val m = NetUtil.maskFromPrefix(prefix); val net = ipInt and m
            val base = NetUtil.intToIp(net).substringBeforeLast('.')
            for (h in intArrayOf(222, 223, 224, 199, 188, 111, 77, 66)) { val c = "$base.$h"; if (c != cameraIp) return c }
            "$base.250"
        } catch (_: Exception) { "192.168.1.250" }
    }

    private fun clearTempIps() { for (t in tempIps) Root.delTempIp(t.first, t.second, t.third); tempIps.clear() }
    private fun launch(url: String) { try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) } catch (e: Exception) { toast(e.message ?: "open failed") } }
    private fun toast(m: String) = runOnUiThread { Toast.makeText(this, m, Toast.LENGTH_LONG).show() }
    private fun today() = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US).format(java.util.Date())
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    // ---- list adapter ----
    inner class DeviceAdapter : BaseAdapter() {
        override fun getCount() = synchronized(lock) { ordered.size }
        override fun getItem(position: Int) = synchronized(lock) { ordered[position] }
        override fun getItemId(position: Int) = position.toLong()
        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val view = convertView ?: layoutInflater.inflate(android.R.layout.simple_list_item_2, parent, false)
            val d = getItem(position)
            val t1 = view.findViewById<TextView>(android.R.id.text1)
            val t2 = view.findViewById<TextView>(android.R.id.text2)
            val brand = if (d.brand.isNotEmpty()) d.brand else "?"
            val typeStr = if (d.type.isNotEmpty() && d.type != "?") "  ·  ${d.type}" else ""
            t1.text = "${d.ip}    $brand$typeStr"
            val bits = listOfNotNull(d.vendor.ifEmpty { null }, d.model.ifEmpty { null }, d.mac.ifEmpty { null }, d.source.ifEmpty { null })
            t2.text = bits.joinToString("  ·  ")
            val reachable = isReachable(d)
            view.setBackgroundColor(when {
                !d.activated -> Color.parseColor("#FFE0E0")
                !reachable -> Color.parseColor("#FFF9D6")
                else -> Color.TRANSPARENT
            })
            return view
        }
    }
}
