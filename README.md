# DNS Sinkhole

A local, on-device DNS sinkhole for Android — similar in spirit to Pi-hole,
but it runs entirely on the phone itself with no external server, router
changes, or root required.

It works by starting a local VPN (via Android's `VpnService` API) that
intercepts only DNS traffic. Every DNS query is checked against a blocklist
of known ad/tracker domains:

- **Blocked domain** → answered immediately on-device with `0.0.0.0` (or
  `::` for AAAA), so the ad/tracker request fails fast instead of loading.
- **Everything else** → forwarded verbatim to a real upstream resolver
  (Cloudflare/Google/Quad9) and the real answer relayed back.

All other (non-DNS) traffic never touches the VPN tunnel and continues over
the normal network path — this is not a full traffic-routing VPN, so there's
no bandwidth/latency overhead for anything but the DNS lookups themselves.

## Features

- Toggle protection on/off from the app, or directly from a persistent
  notification (no need to open the app).
- Runs as a foreground service with a status notification showing how many
  ad/tracker queries have been blocked.
- Bundled starter blocklist (curated list of major ad/analytics/tracker
  domains), with an in-app "Update Blocklist Now" button to refresh from a
  hosts-file style URL (defaults to the StevenBlack hosts list).
- Per-domain whitelist/blacklist support (stored locally).
- Automatically resumes protection after a reboot if it was on before.
- No accounts, no analytics, no data leaves the device except the DNS
  queries it forwards to your chosen resolver.

## Building the APK

Requires the Android SDK (compileSdk 34) and JDK 17+.

```bash
./gradlew assembleDebug
# APK output: app/build/outputs/apk/debug/app-debug.apk

./gradlew assembleRelease
# then sign/zipalign as usual for a release build
```

Install directly over USB:

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Or copy the APK to the phone and install it manually (enable "Install
unknown apps" for whichever app you use to open it).

> **Note:** this project was authored/reviewed in an environment without
> the Android SDK available, so the build itself could not be executed
> here (Google's Maven repo was unreachable). The IP/UDP checksum and DNS
> message logic was independently prototyped and verified in Python before
> being ported to Kotlin, and all files were reviewed by hand for
> consistency — but a real `./gradlew assembleDebug` run in an environment
> with the SDK installed is still recommended before shipping the APK to
> catch anything a static read-through couldn't.

## Usage

1. Open the app and toggle protection **on**. Android will show the
   standard "Connection request" VPN consent dialog the first time — accept
   it (this is a normal part of how any local VPN-based app, including
   ad blockers, works on Android; no traffic leaves the device except your
   normal DNS lookups going to whichever resolver you'd otherwise use).
2. A notification appears showing protection is active, with a "Turn Off"
   action button — tap it any time to disable protection without opening
   the app (and "Turn On" to re-enable it the same way).
3. Use "Update Blocklist Now" in the app to refresh the domain list from
   the configured URL.

## Project layout

```
app/src/main/java/com/sinkhole/adblock/
├── vpn/SinkholeVpnService.kt   VpnService: TUN read loop, block/forward, foreground notification
├── dns/DnsMessage.kt           Minimal DNS query parsing + sinkhole response building
├── net/IpPacketUtils.kt        Raw IPv4/UDP header read/write + checksums
├── blocklist/BlocklistManager.kt  Blocklist loading (bundled asset + remote update), matching
├── notification/               Status notification + its on/off action receiver
├── boot/BootReceiver.kt        Resumes protection after reboot
├── data/PrefsManager.kt        SharedPreferences-backed settings/stats
└── ui/MainActivity.kt          Toggle switch, stats, blocklist update UI
```

## Known limitations

- IPv4 DNS only in this version (IPv6 DNS servers/queries aren't
  intercepted); this covers the vast majority of Android networks, which
  default to IPv4 DNS.
- The bundled blocklist is a curated starting set, not exhaustive — use
  "Update Blocklist Now" for broader coverage from a maintained list.
