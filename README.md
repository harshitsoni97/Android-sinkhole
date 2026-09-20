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
Both IPv4 and IPv6 DNS are handled.

## Features

- Toggle protection on/off three ways: from the app, from a persistent
  notification, or from a **Quick Settings tile** (the pull-down shade next
  to Wi-Fi/Bluetooth — add it via the shade's edit screen).
- Runs as a foreground service with a status notification showing how many
  ad/tracker queries have been blocked.
- Bundled starter blocklist (curated list of major ad/analytics/tracker
  domains), with an in-app "Update Blocklist Now" button to refresh from a
  hosts-file style URL (defaults to the StevenBlack hosts list).
- Per-domain whitelist/blacklist support (stored locally).
- In-app **log viewer** (View Logs → Copy / Share / Clear) for diagnosing
  connectivity issues without needing `adb`/logcat.
- Warns if the system **Private DNS** setting is on, which can interfere
  with local DNS filtering.
- Automatically resumes protection after a reboot if it was on before.
- No accounts, no analytics, no data leaves the device except the DNS
  queries it forwards to your chosen resolver.

## Installing

Prebuilt, debug-signed APKs are published on the repository's
[Releases](../../releases) page — download the latest `dns-sinkhole-*.apk`
to your phone and open it (you'll need to allow "install from unknown
sources" for whichever app you open it with, since it isn't distributed via
the Play Store).

Releases are produced automatically by a GitHub Actions workflow
(`.github/workflows/build-release-apk.yml`) that builds the APK on a
GitHub-hosted runner. Pushing a `v*` tag cuts a tagged release.

## Building the APK yourself

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

## Usage

1. Open the app and toggle protection **on**. Android will show the
   standard "Connection request" VPN consent dialog the first time — accept
   it (this is a normal part of how any local VPN-based ad blocker works on
   Android; no traffic leaves the device except your normal DNS lookups
   going to whichever resolver you'd otherwise use).
2. A notification appears showing protection is active, with a "Turn Off"
   action button — tap it any time to disable protection without opening
   the app (and "Turn On" to re-enable it the same way). You can also add
   the DNS Sinkhole tile to Quick Settings and toggle from there.
3. Use "Update Blocklist Now" in the app to refresh the domain list from
   the configured URL.
4. Use "View Logs" to see live activity (`DNS blocked:` / `DNS resolved:`
   lines) and copy/share logs if something isn't working.

### Testing that blocking works

Visit an ad-blocker test page such as `d3ward.github.io/toolz/adblock`,
or any ad-heavy news site, then open **View Logs** — you should see
`DNS blocked:` lines for ad/tracker domains.

## How it works (implementation notes)

The VPN registers a small private address on the tun interface and a
**separate** address as the DNS server, then routes only that DNS-server
address into the tunnel. This separation matters: a packet destined to an
address assigned to the interface itself is treated as local by the kernel
and never egresses the tun, so the DNS-server address must be distinct from
(but routed alongside) the interface address for queries to actually reach
the app.

DNS queries that arrive on the tunnel are parsed; blocklisted names get a
synthetic `0.0.0.0`/`::` (or NXDOMAIN) answer built on-device, while
everything else is forwarded to an upstream resolver over a `protect()`ed
socket (so the forward itself doesn't loop back through the VPN) and the
reply is relayed back into the tunnel. IPv4 and IPv6 packets are both parsed
and rebuilt, including correct IP/UDP checksums.

## Project layout

```
app/src/main/java/com/sinkhole/adblock/
├── vpn/SinkholeVpnService.kt      VpnService: TUN read loop, block/forward, foreground service
├── dns/DnsMessage.kt              Minimal DNS query parsing + sinkhole response building
├── net/IpPacketUtils.kt           Raw IPv4/IPv6/UDP header read/write + checksums
├── blocklist/BlocklistManager.kt  Blocklist loading (bundled asset + remote update), matching
├── log/SinkholeLog.kt             In-app ring-buffer + file-backed logger
├── notification/                  Status notification + its on/off action receiver
├── tile/SinkholeTileService.kt    Quick Settings tile
├── boot/BootReceiver.kt           Resumes protection after reboot
├── data/PrefsManager.kt           SharedPreferences-backed settings/stats
└── ui/                            MainActivity (toggle/stats/update) + LogViewerActivity
```

## How this compares to Pi-hole

It's the same **core idea** — sinkhole ad/tracker domains at the DNS layer
by answering blocklisted lookups with a dead address — but the deployment
model and scope are different:

| | Pi-hole | DNS Sinkhole (this app) |
|---|---|---|
| Where it runs | A separate always-on machine (Raspberry Pi, server, container) | On the phone itself, no extra hardware |
| Coverage | Every device that uses it for DNS (whole network) | Only the phone it's installed on |
| Works off your home network | No (unless you add a VPN back home) | Yes — on mobile data, any Wi-Fi, anywhere |
| How devices use it | You point the router/DHCP or device DNS at the Pi | A local `VpnService` captures this phone's DNS |
| Blocklist management | Web admin UI, groups, regex, per-client rules, dashboards | Bundled list + one updatable hosts URL + local allow/block |
| Query logging/stats | Rich historical dashboard | Basic on-device counters + a live log view |
| Upstream options | Any resolver, DoH/DoT via extras | Fixed public resolvers (Cloudflare/Google/Quad9) |

**So: equivalent in principle, not in scope.** For a single phone that you
want protected everywhere (including on cellular), this covers the same
"block ads/trackers via DNS" job without running any server. For
whole-home, multi-device coverage with fine-grained rules and dashboards,
Pi-hole is far more capable — and the two can coexist (run Pi-hole at home,
use this on mobile data).

### Shared limitation with Pi-hole

Because this blocks at the DNS level, it blocks whole ad/tracker **domains**.
It can't strip ads served from the same domain as the content (e.g. some
YouTube/Facebook first-party ads) — that requires in-page element hiding
like a browser extension (uBlock Origin). Pi-hole has the exact same
limitation. For third-party ad networks and trackers, DNS blocking is
effective.

## Notes

- The bundled blocklist is a curated starting set, not exhaustive — use
  "Update Blocklist Now" for broader coverage from a maintained list.
- If sites fail to resolve while protection is on, check that the system
  **Private DNS** setting (Settings → Network → Private DNS) is off; the app
  will surface a warning when it detects this.
