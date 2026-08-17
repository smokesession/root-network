// Root Browser user.js
// A Firefox preferences file for use with the .root onion-routing network.
// Modeled on the arkenfox user.js hardening approach (https://github.com/arkenfox/user.js),
// with proxy configuration specific to this project's SOCKS5 client added on top.
//
// NOTE ON HONESTY: this is a prefs-only bundle. It does not include the C++-level
// patches that Tor Browser carries (deeper canvas/letterboxing defenses, etc).
// See browser/README.md for the full caveat.

/* =========================================================================
   SECTION 0: PROXY CONFIGURATION (network-critical, do not disable)
   ========================================================================= */

// Manual proxy configuration.
user_pref("network.proxy.type", 1);

// Route everything through the local root client SOCKS5 proxy.
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", 9050);
user_pref("network.proxy.socks_version", 5);

// CRITICAL: send the raw hostname to the proxy instead of resolving it locally
// first. This is what allows .root addresses to be handled at all (the OS
// resolver has no idea what a .root TLD is), and it also keeps regular DNS
// lookups from leaking outside the circuit.
user_pref("network.proxy.socks_remote_dns", true);

// Also proxy the DNS Firefox does on its own (belt-and-suspenders with the
// remote_dns pref above).
user_pref("network.proxy.socks5_remote_dns", true);

// Do not allow any host to bypass the proxy, and do not fail open to a
// direct connection if the proxy is unreachable. Both of these prevent
// traffic from leaking around the circuit.
user_pref("network.proxy.allow_bypass", false);
user_pref("network.proxy.failover_direct", false);
user_pref("network.proxy.no_proxies_on", "");

// Don't use a PAC file or WPAD/system proxy -- manual config only.
user_pref("network.proxy.autoconfig_url", "");
user_pref("network.proxy.type.mode", 1);

/* =========================================================================
   SECTION 1: DNS
   ========================================================================= */

// Disable DNS prefetching -- prefetch can leak hostnames outside the proxy.
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);

// Disable IPv6 for DNS/connections. IPv6 has historically been a WebRTC /
// direct-connection leak vector when a proxy is only configured for IPv4/
// SOCKS. Optional/aggressive: can break IPv6-only sites, but there are none
// reachable through this proxy anyway.
user_pref("network.dns.disableIPv6", true);

// Disable DNS-over-HTTPS entirely. This is essential: if DoH is left on,
// Firefox can resolve hostnames itself via a public DoH resolver, bypassing
// the SOCKS proxy and defeating remote DNS resolution of .root addresses.
user_pref("network.trr.mode", 5); // 5 = off, TRR disabled entirely
user_pref("network.trr.uri", "");
user_pref("network.trr.custom_uri", "");
user_pref("doh-rollout.disable-heuristics", true);
user_pref("doh-rollout.doorhanger-decision", "UIOk");

// Disable captive portal detection -- it makes unproxied requests to a
// Mozilla-run detection URL on startup/network change.
user_pref("network.captive-portal-service.enabled", false);
user_pref("captivedetect.canonicalURL", "");

// Disable network connectivity checks (also make unproxied requests).
user_pref("network.connectivity-service.enabled", false);

/* =========================================================================
   SECTION 2: WEBRTC LEAK PREVENTION
   ========================================================================= */

// Force WebRTC to only use the configured proxy; never let ICE candidates
// expose the real local/public IP.
user_pref("media.peerconnection.enabled", false); // aggressive: disables WebRTC entirely (breaks video calls). Comment out to just restrict instead.
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);

/* =========================================================================
   SECTION 3: TELEMETRY / DATA COLLECTION / SHIELD / NORMANDY
   ========================================================================= */

user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.coverage.opt-out", true);
user_pref("toolkit.coverage.endpoint.base", "");
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.sessions.current.clean", true);

// Crash reporter
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);

// Shield / Normandy (remote-controlled experiments)
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

// Studies
user_pref("browser.discovery.enabled", false);

/* =========================================================================
   SECTION 4: FINGERPRINTING RESISTANCE
   ========================================================================= */

// Core RFP switch. Aggressive: this changes reported timezone to UTC, spoofs
// screen/window size to fixed buckets (letterboxing), disables some canvas/
// WebGL/font readouts, and can break sites that rely on real viewport size
// or precise timers. It is the single biggest fingerprinting win available
// via prefs, but it is also the most visibly disruptive one.
user_pref("privacy.resistFingerprinting", true);

// Letterboxing: pads the content window to a fixed set of sizes so window
// dimensions can't be used as a fingerprint. Aggressive/cosmetic side effect:
// grey bars around the page. Only takes effect with RFP on.
user_pref("privacy.resistFingerprinting.letterboxing", true);

// Reduce timer precision further (RFP already does this; explicit for clarity).
user_pref("privacy.reduceTimerPrecision", true);

// WebGL: RFP already restricts readback; these disable it outright as a
// second layer. Aggressive: breaks WebGL-dependent sites/games entirely.
user_pref("webgl.disabled", false); // left enabled by default -- flip to true for max hardening at the cost of WebGL content
user_pref("webgl.min_capability_mode", true);
user_pref("webgl.disable-extensions", true);

// Don't expose exact OS/CPU details.
user_pref("privacy.resistFingerprinting.exemptedDomains", "");

// Disable geolocation.
user_pref("geo.enabled", false);
user_pref("geo.provider.network.url", "");

/* =========================================================================
   SECTION 5: HISTORY / CACHE / SANITIZATION ON SHUTDOWN
   ========================================================================= */

// Clear everything on shutdown so no session artifacts persist between runs.
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.history", true);
user_pref("privacy.clearOnShutdown.formdata", true);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.siteSettings", false);

// Also apply the same set to the "clear on shutdown" v2 pref group used by
// newer Firefox releases (harmless if unused on older versions).
user_pref("privacy.clearOnShutdown_v2.historyFormDataAndDownloads", true);
user_pref("privacy.clearOnShutdown_v2.cookiesAndStorage", true);
user_pref("privacy.clearOnShutdown_v2.cache", true);
user_pref("privacy.clearOnShutdown_v2.siteSettings", false);

// Don't remember history at all during the session either.
user_pref("places.history.enabled", false);
user_pref("browser.privatebrowsing.autostart", true);

// Disk cache off -- avoid leaving fetched content on disk.
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.disk.smart_size.enabled", false);
user_pref("browser.cache.offline.enable", false);

// Session restore should not persist form data / session state to disk.
user_pref("browser.sessionstore.privacy_level", 2);

/* =========================================================================
   SECTION 6: MISC PRIVACY / HARDENING
   ========================================================================= */

// Disable form autofill and address/CC storage.
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);
user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);

// Disable predictive/prefetch features that make unproxied or premature
// network requests.
user_pref("network.prefetch-next", false);
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("network.predictor.enabled", false);
user_pref("network.dns.disablePrefetch", true);

// Disable link-mouseover URL prefetching / preconnect on new tab page.
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.ping-centre.telemetry", false);

// Referer trimming (send less cross-origin info).
user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

// Disable Pocket.
user_pref("extensions.pocket.enabled", false);

// Disable Firefox Sync / account prompts.
user_pref("identity.fxaccounts.enabled", false);

// First-party isolation / cookie behavior: block cross-site cookies/tracking
// by default rather than only in a special mode.
user_pref("network.cookie.cookieBehavior", 5); // 5 = total cookie protection (dynamic FPI), current Firefox default for strict tracking protection
user_pref("privacy.firstparty.isolate", true);

// Enhanced Tracking Protection at strict level.
user_pref("browser.contentblocking.category", "strict");
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);

// Disable password/breach alert network calls.
user_pref("signon.management.page.breach-alerts.enabled", false);

/* =========================================================================
   SECTION 7: UPDATES (handled deliberately here, see README)
   ========================================================================= */

// Disable Firefox's built-in auto-update checks/download. Update policy is
// also enforced via policies.json; this is the prefs-level mirror of it.
user_pref("app.update.auto", false);
user_pref("app.update.checkInstallTime", false);
user_pref("app.update.disabledForTesting", true);
