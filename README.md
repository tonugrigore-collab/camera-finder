# Camera Finder — Android

Find every IP camera on the wire, all brands, from your Android camera tester (or phone).
A direct port of the Windows Camera Finder: same discovery engine, same per‑brand reset guide.

## Build it (one time)

I could **not** compile the APK in the sandbox where this was written (Google's Android build
servers are blocked there), so this is the **source project** — you build the APK:

1. Open **Android Studio** → *Open* → pick this folder (`CameraFinderAndroid`).
2. Let it sync Gradle (first time pulls the Android Gradle Plugin + Kotlin — needs internet once).
3. Plug in the tester (USB debugging on) and press **Run** ▶, or
   *Build → Build Bundle(s)/APK(s) → Build APK(s)* and sideload the `app-debug.apk`.

- **minSdk 24** (Android 7) → **target 34**. Kotlin, no exotic dependencies.
- Treat this first build as a **draft**: I wrote it carefully but couldn't run the compiler here.
  Send me any build error and I'll fix it — most would be a one‑line import/signature tweak.

## What it does (same as the Windows app)

- **Find** — ONVIF, Hikvision SADP, Dahua DHIP + DVRIP, Xiongmai/Sofia, plus an ARP sweep.
  Off‑subnet cameras show up too (probes are layer‑2 broadcast) and are shaded yellow.
- **Vendor from MAC** — the full IEEE OUI list (38k makers) names every brand.
- **Tap a camera** → Open in browser · Change IP/settings · Reset help · Factory reset · Reboot · Copy IP.
- **Reset help** — per‑brand physical‑reset steps, button location, hold time, default IP/login.

### Root (camera testers are rooted)

Two things stock Android can't do, which your tester's root enables:
- **Off‑subnet reach** — adds a temporary IP (`ip addr add …`) so you can open/configure a camera in a
  different range, then removes it. Without root, the app tells you the IP to set manually.
- **ARP table** — read for the deep sweep. Without root it may be empty on Android 10+, but the
  discovery protocols still carry MACs for most cameras.

## Selling it — what to do first

- **Vendor database** (`app/src/main/assets/oui.tsv.gz`) is the **public IEEE OUI registry** data
  (prefix → maker), not Nmap's packaged file — fine to ship in a paid app. Refresh any time from
  <https://standards-oui.ieee.org/>.
- **The code is yours** — the discovery/config is written fresh from the protocol formats, not copied
  from any GPL project.
- **Brand names, not logos** — "Works with Hikvision / Dahua" is fair use; don't use their logos.
- **Keep the no‑password‑crack stance** — it's what keeps the app publishable on Play Store and off the
  hacktool lists. The "Reset help" (physical button + manufacturer routes) is the clean alternative.

## File map

```
app/src/main/
  AndroidManifest.xml
  assets/oui.tsv.gz                 IEEE vendor data (prefix <TAB> maker)
  java/com/lutonsec/camfinder/
    MainActivity.kt                 UI, scan, actions, temp-IP, dialogs
    Discovery.kt                    probes + parsers (ONVIF/SADP/Dahua/DVRIP/Xiongmai)
    Protocols.kt                    ONVIF + Hikvision ISAPI, HTTP Digest
    ResetGuide.kt                   per-brand physical reset reference
    Device.kt  NetUtil.kt  Oui.kt  Root.kt
  res/layout/activity_main.xml, res/values/*
```
