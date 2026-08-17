# Root Browser

A preconfigured Firefox bundle for browsing `.root` hidden services and the
regular internet through this project's onion-routing network. It follows the
same architectural pattern as Tor Browser: a hardened *configuration* on top
of stock Firefox (a `user.js` prefs file, `policies.json`, and a launcher),
not a separately built browser engine.

## What it does

`launch-root-browser.sh` / `launch-root-browser.ps1`:

1. Starts `root client --socks-addr 127.0.0.1:9050` in the background — this
   is the SOCKS5 proxy that resolves `.root` addresses and forwards regular
   traffic through onion circuits.
2. Polls the SOCKS port until it's actually listening (with a timeout),
   instead of guessing with a fixed sleep.
3. Launches Firefox with `-profile browser/profile -no-remote`, pointed at
   the bundled profile.
4. When you close the browser window, kills the background client process.

## Prerequisites

- Firefox installed (desktop release; ESR also works).
- The `root` binary built: `cargo build --release` from the project root
  produces `target/release/root` (`root.exe` on Windows).

## Running it

### Windows (PowerShell)

```powershell
cd browser
.\launch-root-browser.ps1
```

Optional flags: `-RootBin <path>`, `-FirefoxPath <path>`, `-SocksAddr host:port`,
`-WaitTimeoutSec <n>`. If `root.exe` or `firefox.exe` aren't found automatically,
pass their paths explicitly.

### Linux / macOS / VPS (bash)

```bash
cd browser
./launch-root-browser.sh
```

Optional flags: `--root-bin <path>`, `--firefox-path <path>`, `--socks-addr host:port`.
Env vars `ROOT_BIN`, `FIREFOX_BIN`, `SOCKS_ADDR`, `WAIT_TIMEOUT` work too.

## How the profile is configured

The `.root` network needs the browser to hand the *hostname* to the SOCKS5
proxy rather than resolving it itself — the OS has no idea what a `.root` TLD
is, only the `root client` process does. The profile sets manual SOCKS5 proxy
config (`127.0.0.1:9050`) with `network.proxy.socks_remote_dns = true`, which
is what makes this work, and locks proxy bypass off so nothing can route
around the circuit.

Everything else in `profile/user.js` is modeled on the [arkenfox
user.js](https://github.com/arkenfox/user.js) hardening approach, grouped by
section:

- **DNS** — prefetching, IPv6, captive-portal/connectivity checks, and
  DNS-over-HTTPS are all disabled. DoH matters most: if left on, Firefox can
  resolve hostnames itself via a public DoH resolver, completely bypassing
  the SOCKS proxy and defeating `.root` resolution.
- **WebRTC** — ICE candidate gathering is restricted to the proxy only (and
  WebRTC is disabled outright by default) so a video-call style connection
  can't leak your real IP around the proxy.
- **Telemetry / Shield / Normandy / crash reporting** — all turned off, so
  the browser doesn't phone home with usage data or accept remote-controlled
  experiments.
- **Fingerprinting resistance** — `privacy.resistFingerprinting` plus
  letterboxing and WebGL restrictions make the browser's fingerprint more
  uniform across installs. This is the most disruptive category: it can
  change reported timezone, window size behavior, and break some WebGL-heavy
  sites. Prefs that are optional/aggressive are commented in `user.js`.
- **History/cache sanitization** — full sanitize-on-shutdown, private
  browsing by default, and disk cache disabled, so nothing persists between
  sessions.
- **Misc hardening** — form/password autofill off, predictive network
  requests (prefetch, speculative connect) off, strict tracking protection,
  Pocket and Sync disabled.

`policies.json` is Firefox's [Enterprise Policy](https://mozilla.github.io/policy-templates/)
mechanism — it locks settings that some prefs can't reliably control (auto
update checks, Pocket, sync/account prompts, homepage) and mirrors the proxy
config as a second layer.

## Honest caveats

- **This is a config bundle, not Tor Browser.** Tor Browser includes actual
  C++-level patches to Firefox beyond what any `user.js`/policy combination
  can express — deeper canvas fingerprinting defenses, more thorough
  letterboxing, first-party isolation edge cases, and a security posture
  that's been independently reviewed over years. This bundle raises the bar
  meaningfully over stock Firefox, but you should not assume it gives
  equivalent anonymity or fingerprinting protection to Tor Browser.
- **First run may still make some network calls prefs don't fully suppress**
  — e.g. certain background update-check plumbing or telemetry pings that
  fire before `policies.json`/`user.js` are fully applied, or ones tied to
  Firefox internals not exposed as a pref at all. `policies.json` disables
  the update checks we know how to disable, but no config bundle can
  guarantee zero first-run network activity on every Firefox version.
- The `network.proxy.socks_remote_dns` pref is the single point of failure
  for `.root` resolution — if a future Firefox release renames or removes
  it, this bundle needs updating.

## Pref confidence notes (for review before shipping)

**Confirmed real Firefox prefs (high confidence):**
`network.proxy.type`, `network.proxy.socks`, `network.proxy.socks_port`,
`network.proxy.socks_version`, `network.proxy.socks_remote_dns`,
`network.proxy.allow_bypass`, `network.proxy.failover_direct`,
`network.proxy.no_proxies_on`, `network.dns.disablePrefetch`,
`network.trr.mode`, `network.trr.uri`, `media.peerconnection.enabled`,
`media.peerconnection.ice.default_address_only`,
`media.peerconnection.ice.no_host`, `toolkit.telemetry.enabled`,
`datareporting.healthreport.uploadEnabled`,
`datareporting.policy.dataSubmissionEnabled`, `app.shield.optoutstudies.enabled`,
`app.normandy.enabled`, `privacy.resistFingerprinting`,
`privacy.resistFingerprinting.letterboxing`, `privacy.sanitize.sanitizeOnShutdown`,
`privacy.clearOnShutdown.*`, `places.history.enabled`,
`browser.privatebrowsing.autostart`, `browser.cache.disk.enable`,
`signon.rememberSignons`, `network.cookie.cookieBehavior`,
`privacy.trackingprotection.enabled`, `extensions.pocket.enabled`,
`identity.fxaccounts.enabled`, `app.update.auto`.

**Included based on the arkenfox reference but not independently
re-verified against current Firefox source (worth a spot-check before
shipping):**
`network.proxy.socks5_remote_dns` (arkenfox-style alias some versions use
alongside `socks_remote_dns` — likely redundant/harmless if not read),
`media.peerconnection.ice.proxy_only_if_behind_proxy`,
`webgl.min_capability_mode`, `webgl.disable-extensions`,
`network.captive-portal-service.enabled`, `captivedetect.canonicalURL`,
`network.connectivity-service.enabled`, `doh-rollout.disable-heuristics`,
`doh-rollout.doorhanger-decision`, `toolkit.telemetry.newProfilePing.enabled`,
`toolkit.telemetry.updatePing.enabled`, `toolkit.telemetry.bhrPing.enabled`,
`toolkit.coverage.opt-out`, `toolkit.coverage.endpoint.base`,
`browser.discovery.enabled`, `privacy.firstparty.isolate` (largely
superseded by `network.cookie.cookieBehavior` total-cookie-protection in
modern Firefox, kept for defense-in-depth on older versions),
`privacy.clearOnShutdown_v2.*` (newer-version pref group, harmless no-op if
the running Firefox doesn't use it), `network.predictor.enabled`,
`browser.urlbar.speculativeConnect.enabled`,
`network.http.speculative-parallel-limit`,
`browser.sessionstore.privacy_level`, `app.update.checkInstallTime`,
`app.update.disabledForTesting` (test-only pref; harmless if ignored in a
release build, included defensively).

`policies.json` keys were written against the documented Firefox Enterprise
Policy schema (`DisableAppUpdate`, `DisableTelemetry`, `DisablePocket`,
`Proxy`, `DNSOverHTTPS`, `EnableTrackingProtection`, `UserMessaging`, etc.) —
these are standard, well-documented policy names, but the exact set of
sub-keys accepted per Firefox version (e.g. all fields under `Proxy` or
`UserMessaging`) was not re-verified against a live current build and is
worth a spot-check.
