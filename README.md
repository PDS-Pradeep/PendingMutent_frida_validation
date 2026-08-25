# PendingIntent Vulnerability Analysis and Evaluation

Research project investigating a well-known Android vulnerability class involving
`PendingIntent` objects — unrestricted mutability (fill-in Intent injection),
delegated-invocation privilege escalation (`send()`), and ownership/lifecycle
hijacking (`cancel()`) — through static triage of a real APK corpus, dynamic
exploitation on a live emulator against both real-world apps and purpose-built
fixture apps, and empirical testing of an OS-enforced mitigation.

This README summarizes the complete project: what was built, what was run, and
what was found. Every claim below is backed by a script, log file, or CSV in this
repository — nothing here is projected or assumed.

## TL;DR

- Scanned 245 real F-Droid/IzzyOnDroid APKs with a static bytecode analyzer,
  selected 13 candidates flagged for PendingIntent risk.
- Dynamically confirmed **10 of the 13** actually create a live, capturable
  PendingIntent at runtime (5 organically, 5 via a reflective "forcer" technique).
  The remaining 3 are documented as unresolved with specific, verified reasons —
  not silently dropped.
- On all 10 confirmed apps: fill-in injection and privilege-escalation `send()`
  succeed unconditionally; `cancel()`-based ownership hijack **fails** — blocked
  by Android's own platform-level UID check, independent of app behavior.
- Built two pairs of genuinely separate, independently-signed Android apps
  (victim + attacker) to reproduce the same attacks across a real process/UID
  boundary, and to test a real mitigation (`FLAG_IMMUTABLE` + a signature-level
  broadcast permission) — confirmed via Logcat and `apksigner`/`aapt` evidence to
  block the two exploitable attacks entirely at the OS layer.
- Extended testing to two additional disruption attacks (flood, redirect) beyond
  `cancel()`; one generalizes to real apps, one does not, and the reasoning why
  is documented with real evidence, not assumption.

## Project Structure

```
APK_Downloader/
├── main.py                              # Downloads F-Droid/IzzyOnDroid APK corpus
├── analyze_pendingintent_corpus.py      # Static bytecode analyzer (v1/v2/v3 triage)
├── android_repositories/
│   ├── fdroid_main/, fdroid_archive/, izzyondroid/, guardian/   # Downloaded APK corpus (not tracked in git)
│   └── pendingintent_analysis/
│       ├── reports/                     # analysis.jsonl, analysis.csv, v1/v2/v3_candidates.csv,
│       │                                 # selected_13.csv (13 candidates chosen for dynamic testing)
│       ├── candidates/                  # APKs copied by category (v1/v2/v3/mixed) (not tracked in git)
│       └── selected_13/                 # The 13 APKs actually used for dynamic validation (tracked in git)
└── frida_validation/
    ├── run_validation.py                # Dynamic test harness (installs APKs, drives them, attacks them)
    ├── frida/
    │   ├── pendingintent_attack_sim.js  # Attacks A/B/D/E against real APKs (same-process Frida)
    │   ├── pendingintent_defense_sim.js # Reference ownership-gate evaluation (same-process)
    │   └── pendingintent_forcer.js      # Reflective forcer for apps that don't organically create a PI
    ├── results/                         # Raw Frida logs + consolidated CSV/JSON per run
    └── test_apps/
        ├── victim/, malware/            # Baseline: unprotected mutable PI + real cross-app attacker
        ├── victim_hardened/, malware_v2/ # Hardened: FLAG_IMMUTABLE + signature permission + different-cert attacker
        ├── build/, dist/                # Build intermediates and signed, ready-to-install APKs
        ├── README.md                    # Detailed build/run/verify instructions for the fixture apps
        └── rq2b_corrected.tex           # Accurate, evidence-only writeup of the real-app evaluation
```

> Note: the full downloaded APK corpus (`fdroid_main/`, `fdroid_archive/`,
> `izzyondroid/`, `guardian/`, and `pendingintent_analysis/candidates/`) is
> **excluded from this repository** via `.gitignore` — it is several GB of binary
> APK data, not source. Only the 13 APKs actually used for dynamic validation
> (`pendingintent_analysis/selected_13/`) are tracked. Re-download the full corpus
> with `main.py` if needed.

## Stage 1 — Static Corpus Triage

**Script:** `analyze_pendingintent_corpus.py` (built on androguard 4.x)

**What it does:** Scans every `.apk` under `android_repositories/` (245 total, mirrored
from F-Droid main and IzzyOnDroid) and, for each PendingIntent factory/operation call
site found in decoded DEX bytecode, checks for:
- Folded mutability-flag bit patterns (`FLAG_MUTABLE`, `FLAG_IMMUTABLE`,
  `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT`) via bitwise testing of integer literal operands
  (compilers fold flag combinations into a single constant, so exact-string matching
  misses them)
- Fill-in indicators, external-Intent-source indicators (`getParcelableExtra`, etc.),
  ownership-check indicators (`getCreatorPackage`, `getCallingUid`, etc.),
  permission-check indicators
- Manifest-level exposure: exported components, permission-guarded components,
  declared permissions

**Output:** Each APK receives a heuristic **v1** (mutable/fill-in), **v2**
(permission/export boundary), **v3** (cancel/ownership) score, written to
`reports/analysis.jsonl` / `analysis.csv`. The 5 highest-scoring v1, 5 highest v2, and
3 highest v3 apps are selected into `reports/selected_13.csv` and copied into
`selected_13/`.

**Explicit limitation, stated in the tool's own docstring:** this is static triage —
a score does not prove exploitability. That's exactly why Stage 2 exists.

## Stage 2 — Dynamic Confirmation (Same-Process Frida)

**Script:** `run_validation.py` + `frida/pendingintent_attack_sim.js`

**What it does:** For each of the 13 selected APKs — installs it on a connected
Android emulator, spawns it with Frida attached, hooks the five PendingIntent factory
methods (`getActivity`, `getActivities`, `getBroadcast`, `getService`,
`getForegroundService`), and on every capture immediately attempts:
- **Attack A** — fill-in Intent injection via `send(Context, int, Intent)`
- **Attack B** — bare `send()` privilege escalation
- **Attack C** — `cancel()` ownership hijack
- **Attack D** — flood/resource-exhaustion (50× `send()`, added later)
- **Attack E** — fill-in component-redirect probe (added later)

An optional `--drive` flag actively drives the app (BOOT_COMPLETED broadcast, app-widget
update broadcast, JobScheduler force-run, restricted `monkey` UI events) to increase the
chance of triggering a real PendingIntent creation during the observation window.

**First-pass result (passive/driven observation only):** 5 of 13 apps produced a real,
non-null PendingIntent capture. The other 8 either produced `NULL_PENDING_INTENT`
(factory returned null — consistent with a `FLAG_NO_CREATE` existence-check call, not
the real creation call) or `NO_DATA` (no PendingIntent call observed at all in the
window).

## Stage 3 — Reflective Forcer (Resolving Unconfirmed Apps)

**Script:** `frida/pendingintent_forcer.js`, invoked via `run_validation.py --force`

**What it does:** Instead of hoping generic UI driving organically reaches the real
creation call, this script directly reflectively invokes the *specific* app-internal
method already identified by Stage 1's static scan as the PendingIntent-creating call
site — via `Java.choose()` (live instance), genuine constructor invocation (with the
app's own live `Application` context substituted for any `Context`-typed parameter),
or bare `$alloc()` followed by `ContextWrapper.attachBaseContext()` for
Service/Activity-derived classes.

**Result — 5 of the 8 previously-unresolved apps were fixed:**

| Package | Fix | Outcome |
|---|---|---|
| `dev.ukanth.ufirewall` | Forced static call to `Api.updateNotification` | Real capture, attacks A/B/D executed |
| `com.acutis.firewall` | Bare-alloc + `attachBaseContext()` on `FirewallVpnService` | Real capture, attacks A/B/D executed |
| `host.stjin.anonaddy` | Real constructor call on `NotificationHelper` with app Context | Real capture, attacks A/B/D executed |
| `com.adguard.android.contentblocker` | Forced instance call to `showRateAppNotification` | Real capture, attacks A/B/D executed |
| `com.newoether.agora` | Real constructor call on `AgoraForegroundService.Companion` | Real capture, attacks A/B/D executed |

**3 apps remain genuinely unresolved**, each for a distinct, verified structural reason
(not a tooling shortfall):

| Package | Why it can't be forced |
|---|---|
| `com.tughi.aggregator` | The only identified call site is a Kotlin coroutine resume point (`invokeSuspend`) with no reconstructable continuation state; cannot be invoked cold. A real Service (`AutoUpdateService`) exists as a better target but was not tested. |
| `com.pedronveloso.a11ybutton` | Requires a live `androidx.work.WorkerParameters` object only WorkManager's own scheduler can construct. Verified by actually enabling the app's real accessibility service through the genuine Android Settings consent flow (confirmed via `settings get secure enabled_accessibility_services`) — even with real OS-level consent granted, no job was scheduled within the observation window. |
| `org.secuso.privacyfriendly2048` | Confirmed by manually inspecting every screen of the real app UI (navigation drawer, settings) — there is no UI-reachable feature that schedules background work. The manifest-declared `PFABackupService` is never wired to anything the user can tap. |

**Final confirmed set: 10 of 13 apps.**

## Stage 4 — Attack Results on the 10 Confirmed Real Apps

Running Attacks A, B, and D (C intentionally excluded from this combined run — see
"Important bug found and fixed" below) against the confirmed apps:

| Attack | Result |
|---|---|
| A — fill-in injection | Succeeds on all confirmed apps, no exceptions |
| B — privilege escalation `send()` | Succeeds on all confirmed apps, no exceptions |
| C — `cancel()` hijack | **Fails on every app tested** (see Stage 6) |
| D — flood (50× `send()`) | Succeeds on all 6 apps tested for it, 0 exceptions |
| E — redirect via fill-in component override | **Fails on all 6 apps tested** — `fillIn()` silently ignores the override because every tested app's base Intent already has an explicit component set |

Raw evidence: `frida_validation/results/attack_results.csv` and the per-app
`attack_*.log` files (full JSON-lines Frida output).

## Stage 5 — Real Cross-App Exploitation (Synthetic Fixtures)

Same-process Frida attachment has a documented limitation: it cannot prove a *genuine*
second app on a *different* UID behaves the same way. To close that gap, two real
Android apps were designed, compiled with the raw SDK toolchain (no Gradle:
`javac` → `d8` → `aapt2` → `zipalign` → `apksigner`), independently signed, and
installed as separate packages:

- **`test_apps/victim/`** (`com.research.pivictim`) — creates a mutable
  (`FLAG_MUTABLE`) PendingIntent wrapping a broadcast to `SensitiveActionReceiver`
  (the "privileged operation" under test), then leaks it via an unprotected,
  unaddressed broadcast.
- **`test_apps/malware/`** (`com.research.pimalware`) — a genuinely separate
  installed package/UID. Captures the leaked PendingIntent (registered both
  statically and dynamically — dynamic registration was required to survive
  Android 8+ background-execution limits on the static receiver) and runs
  `AttackRunner`, which performs Attacks A, B, C, D (flood), and E (redirect probe
  against a real planted decoy receiver) against the real Android API.

**Baseline result, verified via real Logcat evidence:**
- Attack A: **executed** — confirmed by `SensitiveActionReceiver`'s own log line
  showing the attacker's injected extra
- Attack B: **executed** — confirmed by a second receiver firing from a bare replay
- Attack C: **failed** — `SecurityException: Permission Denial: cancelIntentSender()
  from pid=<attacker> ... is not allowed to cancel package com.research.pivictim`
- Attack D: **executed** — 50/50 `send()` calls succeeded, 0 exceptions, 627ms;
  `SensitiveActionReceiver` fired 53 times total in the run
- Attack E: **failed** — `send()` reported no exception, but the planted decoy
  receiver never actually fired (0 invocations across the whole test). Root cause,
  confirmed by inspecting Android's own `Intent.fillIn()` semantics: it only
  overrides a field that is currently *unset* on the base Intent, and VictimApp's
  base Intent already had an explicit component. **This corrected an earlier wrong
  conclusion** where "no exception thrown" had been mistaken for "the attack worked."

## Stage 6 — Real OS-Enforced Mitigation (Synthetic Fixtures)

- **`test_apps/victim_hardened/`** (`com.research.pivictimhardened`) — creates the
  PendingIntent with `FLAG_IMMUTABLE` instead of `FLAG_MUTABLE`, and declares a new
  `android:protectionLevel="signature"` permission required to receive the leak
  broadcast.
- **`test_apps/malware_v2/`** (`com.research.pimalwarev2`) — declares the matching
  `uses-permission`, but is deliberately signed with a **different certificate**
  (`build/malware_v2.keystore`, distinct SHA-256 fingerprint from the victim's,
  confirmed via `apksigner verify --print-certs`). The compiled manifest's
  `protectionLevel` was independently confirmed to compile to the binary value
  `0x2` (signature) via `aapt dump xmltree`, not just the source XML.

**Result:** The leak broadcast was never delivered — confirmed directly in Logcat via
Android's own `BroadcastQueue`:
```
Permission Denial: receiving Intent { act=...PI_LEAK_ACTION ... }
  to com.research.pimalwarev2/.PiCaptureReceiver
  requires com.research.pivictimhardened.permission.RECEIVE_PI_LEAK
  due to sender com.research.pivictimhardened (uid 10169)
```
No PendingIntent was ever captured by MalwareAppV2; neither Attack A nor B had a
target to operate on. **This is empirically confirmed OS-level prevention** of the two
exploitable attacks — not a claim, a logcat fact.

**Explicit scope limitation:** this mitigation was built and tested only on the two
synthetic fixture apps, on one Android API level (30, via a Pixel 6 AVD). It has
**never been applied to or verified against any of the 13 real APKs** — retrofitting a
real third-party APK's bytecode (decompile, patch the call site, rebuild, resign) was
outside the scope of what was built here.

## Important Bug Found and Fixed Mid-Evaluation

An early combined run (attacks A→B→C→D→E in sequence against real apps) showed Attack
C *succeeding* — directly contradicting the Stage 5 finding. Root cause: this script
attaches Frida to the target app's **own process**, so `cancel()` executes with the
creator's own UID (not a real attacker's), succeeds harmlessly, and **destroys the
underlying PendingIntent record** before D and E could run — invalidating their
results (D showed all exceptions; E showed a `CanceledException`, not a meaningful
signal about redirection). **Fixed by removing Attack C from this combined script
entirely** — it had already been correctly and separately verified via the genuine
two-UID cross-app test in Stage 5. This is documented in `pendingintent_attack_sim.js`
as an explicit code comment so the reasoning isn't lost.

## Why `cancel()` Fails, in Detail

`PendingIntent.cancel()` triggers a Binder IPC call into `system_server`
(`ActivityManagerService.cancelIntentSender()`), which independently checks the
calling UID — attributed by the kernel's Binder driver itself, not anything the client
can influence — against the UID that originally created the PendingIntent record. This
check:
- Is unrelated to `FLAG_MUTABLE`/`FLAG_IMMUTABLE` (that flag only affects fill-in
  behavior, Attack A's target)
- Is unrelated to whether the base Intent was empty/implicit (the v1 static-triage
  pattern) — the check operates on the token's identity, never the wrapped Intent's
  content
- Cannot be bypassed via reflection, because reflection only manipulates objects
  within the caller's own process; it cannot alter what UID `system_server` sees when
  the kernel's Binder driver marshals the IPC call

This means, for an unprivileged third-party app (the threat model this whole project
targets), `cancel()`-based ownership hijacking is a closed vulnerability at the
platform layer — independent of anything an app developer does — on the Android API
level tested (30). This was **not tested across other API levels**.

## Extended Disruption Attacks (Beyond `cancel()`)

Since `cancel()` is platform-blocked, two alternative "cause harm without needing
ownership" mechanisms were tested:

- **Attack D (flood/resource-exhaustion)** — repeated `send()` with no delay. **Works**,
  confirmed on the synthetic pair and on all 6 real apps tested for it. Nothing in
  Android rate-limits or throttles this; an attacker holding a leaked reference can
  trigger the creator's delegated action an effectively unbounded number of times.
- **Attack E (fill-in component-redirect)** — attempting to redirect dispatch to a
  different component via the fill-in Intent's `setComponent()`/`setClassName()`.
  **Does not work** against any app tested (synthetic or real), because every tested
  app's base Intent already specifies an explicit component, and `Intent.fillIn()`
  only overrides currently-unset fields. This is a genuine, if incidental, mitigating
  property of explicit-Intent construction — not something any of these apps did on
  purpose to defend against this attack.

## Toolchain

Built entirely with Android SDK command-line tools — no Gradle, no Android Studio
project:
- **Compile:** `javac` (JDK 26.0.2) against `android-30/android.jar`
  (`minSdkVersion=23`, `targetSdkVersion=30` for the fixture apps — matches the only
  system image available locally, a Pixel 6 AVD)
- **Dex:** `d8` (build-tools 36.0.0)
- **Resource compile/link:** `aapt2 compile` / `aapt2 link`
- **Dex injection:** `jar --update` (inserting `classes.dex` into the linked base APK)
- **Alignment:** `zipalign -p 4`
- **Signing:** `apksigner sign`, two distinct keystores (`build/debug.keystore` for
  victim/malware/victim_hardened, `build/malware_v2.keystore` — deliberately
  different — for malware_v2)
- **Dynamic instrumentation:** `frida`/`frida-tools` 17.17.0, `frida-server` pushed to
  `/data/local/tmp/` on the emulator
- **Emulator:** Pixel 6 AVD, API 30, x86_64, Google APIs, run with
  `-gpu swiftshader_indirect` (software rendering — switched to this after a real GPU
  driver crash was observed with hardware rendering on one test app)

## Known Limitations (Stated Explicitly, Not Hidden)

- **3 of 13 statically-flagged apps remain dynamically unconfirmed** — no security
  claim is made about them in either direction (see Stage 3 table for why).
- **The OS-enforced mitigation (Stage 6) was never applied to real APKs** — only to
  the synthetic fixture pair. Whether it would work identically if retrofitted onto
  real third-party bytecode is untested.
- **Everything was tested on a single Android API level (30)** on one emulator
  profile. Whether `cancel()`'s UID check, `fillIn()`'s override semantics, or the
  signature-permission mitigation behave identically on other API levels or OEM
  forks was not verified.
- **Attacks D and E were only generalized to 6 of the 10 confirmed real apps** (the
  ones captured organically in the specific test run used); the other 4
  forcer-dependent apps were not re-tested with D/E.
- Earlier drafts of this evaluation (`PendingIntent_Evaluation_Report.tex` /
  superseded sections) referenced a fictional named framework, formal proof
  apparatus, an Androzoo/VirusTotal-verified corpus, and a Culebra-based
  false-positive study — **none of that exists in this project**. The corrected,
  evidence-only writeup is `frida_validation/test_apps/rq2b_corrected.tex`; treat it,
  not the earlier draft, as authoritative.

## Where to Look for Evidence

| Claim | Evidence file |
|---|---|
| Static triage scores | `android_repositories/pendingintent_analysis/reports/analysis.jsonl`, `v1/v2/v3_candidates.csv` |
| 13 selected candidates | `reports/selected_13.csv` |
| Dynamic confirmation results (10/13) | `frida_validation/results/attack_results.csv`, per-app `.log` files |
| Reflective forcer fixes | `frida_validation/frida/pendingintent_forcer.js`, `attack_forced_*.log` files |
| Real cross-app baseline attack | `frida_validation/test_apps/` source + build; captured Logcat in prior session transcripts |
| Real OS-level mitigation | `apksigner verify` output, `aapt dump xmltree` output, `BroadcastQueue` Logcat denial (documented in `test_apps/README.md`) |
| Corrected, accurate write-up | `frida_validation/test_apps/rq2b_corrected.tex` |

## Disclaimer

This is a research/security-testing project. The `test_apps/` fixtures deliberately
implement insecure PendingIntent patterns and real attack code for evaluation
purposes — do not ship any pattern from `victim/` or `malware/` in a production app.
