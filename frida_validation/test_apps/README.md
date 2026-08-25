# PendingIntent Cross-App Test Fixtures (VictimApp / MalwareApp)

Research/test-only APKs built to close the gap noted in `pendingintent_defense_sim.js`'s
own docstring: the Frida harness attacks/gates a PendingIntent from *inside the same
process* as the app that created it (synthetic non-creator label, no real second UID).
These two APKs are a genuine two-app, two-UID reproduction of the same three attacks
(A: fill-in injection, B: send() privilege escalation, C: cancel() ownership hijack),
so `pendingintent_defense_sim.js` can be evaluated against a real cross-process capture
instead of only a same-process simulation.

## What each app does

**VictimApp** (`com.research.pivictim`)
- `MainActivity.onCreate()` creates a **mutable** `PendingIntent` (`FLAG_MUTABLE |
  FLAG_UPDATE_CURRENT`) wrapping a broadcast to `SensitiveActionReceiver`.
- Immediately leaks that PendingIntent via an **unprotected, exported broadcast**
  (`com.research.pivictim.PI_LEAK_ACTION`, extra key `leaked_pi`) — no signature or
  permission restriction, deliberately reproducing the v1/v2/v3 exposure pattern the
  static analyzer flags.
- `SensitiveActionReceiver` is the "privileged operation": every time it fires, it logs
  to logcat (tag `PIVictim`) and appends a line to internal file `executed.txt`, whether
  it was invoked by the app's own PendingIntent.send() or by anyone else calling
  `.send()` on the captured reference.

**MalwareApp** (`com.research.pimalware`)
- Separate package → separate UID, assigned by PackageManager at install time. This is
  the real cross-process boundary the Frida harness could not exercise.
- `PiCaptureReceiver` (exported) listens for `PI_LEAK_ACTION`, extracts the leaked
  `PendingIntent` Parcelable, and hands it to `AttackRunner`.
- `AttackRunner` runs the three real attacks against the live Android API and logs
  each outcome to logcat (tag `PIMalware`) as `EXECUTED` / `SECURITY_EXCEPTION` /
  `EXCEPTION`, matching the vocabulary already used in `attack_results.csv` /
  `defense_results.csv` so results are directly comparable.

## Build artifacts

```
test_apps/
  victim/            AndroidManifest.xml, src/, res/   (unprotected baseline)
  malware/           AndroidManifest.xml, src/, res/   (unprotected baseline attacker)
  victim_hardened/   AndroidManifest.xml, src/, res/   (FLAG_IMMUTABLE + signature permission)
  malware_v2/        AndroidManifest.xml, src/, res/   (attacker, different signing cert)
  build/             intermediate classes/dex + keystores:
                       debug.keystore       pass "android", alias androiddebugkey
                                             (shared by victim, malware, victim_hardened)
                       malware_v2.keystore  pass "malwarev2", alias malwarev2key
                                             (malware_v2 only — deliberately different cert)
  dist/
    pivictim.apk          signed, ready to install
    pimalware.apk         signed, ready to install
    pivictimhardened.apk  signed, ready to install
    pimalwarev2.apk       signed, ready to install
```

All four apps are `minSdkVersion=23`, `targetSdkVersion=30` (matching the only system
image available locally: Pixel 6 AVD, `android-30/google_apis/x86_64`). `FLAG_IMMUTABLE`
and the `FLAG_MUTABLE` bit value (`0x02000000`, used directly since the named constant
was only added in API 31) are both available from API 23 onward — only *mandatory*
starting API 31 — so this works identically on API 30. Built entirely with SDK
command-line tools (no Gradle): `javac` → `d8` → `aapt2 compile/link` → inject dex with
`jar --update` → `zipalign` → `apksigner sign`, using the debug keystore under
`build/debug.keystore`.

## Rebuilding (if sources change)

```powershell
$sdk = "C:\Users\Admin\AppData\Local\Android\Sdk"
$jdk = "D:\Java\jdk-26.0.2\bin"
$aapt2 = "$sdk\build-tools\36.0.0\aapt2.exe"
$d8    = "$sdk\build-tools\36.0.0\d8.bat"
$zipalign  = "$sdk\build-tools\36.0.0\zipalign.exe"
$apksigner = "$sdk\build-tools\36.0.0\apksigner.bat"
$androidJar = "$sdk\platforms\android-37.0\android.jar"
$root = "d:\APK_Downloader\frida_validation\test_apps"
$ks = "$root\build\debug.keystore"

foreach ($app in "victim","malware") {
  $pkg = if ($app -eq "victim") { "com.research.pivictim" } else { "com.research.pimalware" }

  Remove-Item -Recurse -Force "$root\build\$app\classes" -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path "$root\build\$app\classes","$root\build\$app\dex","$root\build\$app\compiled_res" | Out-Null

  $srcFiles = Get-ChildItem -Recurse -Filter "*.java" "$root\$app\src" | ForEach-Object { $_.FullName }
  & $jdk\javac.exe -source 8 -target 8 -bootclasspath $androidJar -classpath $androidJar -d "$root\build\$app\classes" $srcFiles

  $classFiles = Get-ChildItem -Recurse -Filter "*.class" "$root\build\$app\classes" | ForEach-Object { $_.FullName }
  & $d8 --lib $androidJar --output "$root\build\$app\dex" $classFiles

  & $aapt2 compile --dir "$root\$app\res" -o "$root\build\$app\compiled_res"
  $flata = Get-ChildItem "$root\build\$app\compiled_res" -Filter "*.flat" | ForEach-Object { $_.FullName }
  & $aapt2 link -o "$root\build\$app\base.apk" -I $androidJar --manifest "$root\$app\AndroidManifest.xml" $flata --auto-add-overlay

  Copy-Item "$root\build\$app\base.apk" "$root\build\$app\unsigned.apk" -Force
  Push-Location "$root\build\$app\dex"; & $jdk\jar.exe --update --file "$root\build\$app\unsigned.apk" classes.dex; Pop-Location

  & $zipalign -f -p 4 "$root\build\$app\unsigned.apk" "$root\build\$app\aligned.apk"
  & $apksigner sign --ks $ks --ks-pass pass:android --ks-key-alias androiddebugkey --key-pass pass:android --out "$root\dist\pi$app.apk" "$root\build\$app\aligned.apk"
}
```

## Installing and running (requires a connected device/emulator — none is attached right now)

```powershell
adb devices                              # confirm exactly one device/emulator
adb install -r "d:\APK_Downloader\frida_validation\test_apps\dist\pivictim.apk"
adb install -r "d:\APK_Downloader\frida_validation\test_apps\dist\pimalware.apk"

# Baseline (no defense): launch MalwareApp, which also launches VictimApp.
adb shell am start -n com.research.pimalware/.MainActivity
adb logcat -s PIVictim:I PIMalware:I -v time

# Expected in baseline logcat:
#   PIVictim: Created mutable PendingIntent ... / Leaked PendingIntent via broadcast ...
#   PIMalware: PI_CAPTURED pendingIntent=... creatorPackage=com.research.pivictim creatorUid=<victim_uid> thisPackage=com.research.pimalware thisUid=<malware_uid>
#   PIMalware: {"attack":"A_fillin_injection","status":"EXECUTED"}
#   PIMalware: {"attack":"B_privilege_escalation","status":"EXECUTED"}
#   PIMalware: {"attack":"C_cancel_hijack","status":"EXECUTED"}
#   PIVictim: SensitiveActionReceiver fired: EXECUTED ... attackExtra=A_fillin_injection_from_pimalware  (proves cross-app injection)
```

### Testing `pendingintent_defense_sim.js` against this real capture

The defense script attaches to a **single** target process via `frida -f <package>`. To
evaluate it against VictimApp's real, cross-process-leaked PendingIntent:

1. Attach Frida to **VictimApp** (the creator) so `hookAndGate()` intercepts VictimApp's
   own `PendingIntent.getBroadcast()` call and evaluates the ownership gate the moment
   the PendingIntent is created — before or as it is leaked:
   ```
   frida -D <serial> -f com.research.pivictim -l pendingintent_defense_sim.js -q
   ```
   then separately launch MalwareApp (`adb shell am start -n com.research.pimalware/.MainActivity`)
   to trigger the leak+capture+attack sequence. This shows what the gate *would* decide
   for the real captured PendingIntent (`creatorPackage=com.research.pivictim`), evaluated
   against the script's `SIMULATED_MALWARE_PACKAGE` label — the same limitation described
   in the script's own docstring: it is evaluating decision logic inside the creator's
   process, not intercepting the attacker's real Binder call into `PendingIntent.send()`/`cancel()`.

2. To see whether the gate's policy, if actually enforced, would have stopped the *real*
   MalwareApp attacks recorded above, compare `creatorPackage` from step 1's `PI_CAPTURED`
   log against MalwareApp's real package name (`com.research.pimalware`) logged in its own
   `PI_CAPTURED` event. Since they differ, `authorize()` would return `DENY` for all three
   operations — consistent with the existing `defense_results.csv` semantics, but now
   backed by a real second app/UID rather than only a synthetic label.

3. **Genuine enforcement does NOT come from an in-receiver ownership check.** A tempting
   next step is "port `authorize()` into `SensitiveActionReceiver.onReceive()` and check
   the real caller with `Binder.getCallingUid()`." This does not work: when Android
   delivers a broadcast triggered by `PendingIntent.send()`, the receiver is invoked with
   no reliable signal identifying which process called `.send()` on the PendingIntent —
   the delegation model is the entire point of PendingIntent (it runs with the *creator's*
   authority, regardless of invoker). `Binder.getCallingUid()` inside `onReceive()`
   typically reflects the broadcast dispatcher, not MalwareApp's UID. Any check written
   there is guessing, not enforcement.

   Real prevention requires OS-enforced controls applied **upstream, at creation/delivery
   time** — see `victim_hardened/` and `malware_v2/` below, which implement and verify
   exactly that.

## Known limitations of this fixture (VictimApp / MalwareApp, unprotected baseline)

- `SensitiveActionReceiver` has no ownership check of its own — it always executes and
  logs. This is intentional: it is the *unprotected baseline* the defense gate is meant
  to be compared against.
- The broadcast leak channel (`PI_LEAK_ACTION`) is unrealistically direct compared to
  real-world leaks (e.g. via a shared SDK, clipboard, or file), but it removes any
  dependency on UI automation to trigger PendingIntent creation, unlike scanning
  pre-existing F-Droid APKs where `pi_captured` was frequently 0 (see
  `attack_results.csv` / `defense_results.csv` for `com.tughi.aggregator`,
  `dev.ukanth.ufirewall`, `com.acutis.firewall`, `org.secuso.privacyfriendly2048`).
- Tested on-device on a Pixel 6 AVD (API 30, x86_64) — see the "Actual on-device result"
  sections below for both scenarios' real logcat evidence.
- MalwareApp/MalwareAppV2 register `PiCaptureReceiver` dynamically via
  `Context.registerReceiver()` (in addition to the static manifest declaration), because
  Android 8+ (API 26+) background execution limits drop most broadcasts to a manifest
  receiver once the app isn't foregrounded — which happens here, since launching the
  victim's activity backgrounds the malware app moments later. This is also how real
  malware often works around the same restriction. It does not weaken the
  signature-permission test: permission checks are enforced at delivery time by
  `BroadcastQueue` regardless of how the receiver was registered.

---

## Part 2: Hardened variant — real OS-enforced prevention (VictimAppHardened / MalwareAppV2)

Since in-receiver ownership checks don't work (see above), this variant applies the two
mitigations Android actually enforces, to test whether they genuinely block the same
three attacks rather than just evaluate policy logic.

**VictimAppHardened** (`com.research.pivictimhardened`, signed with `build/debug.keystore`,
same cert as `pivictim.apk`/`pimalware.apk`, CN=`Android Debug`):
- Declares a new permission, `com.research.pivictimhardened.permission.RECEIVE_PI_LEAK`,
  with `android:protectionLevel="signature"`. PackageManager will only grant a
  signature-level permission to an app signed with the **same certificate** as the app
  that declared it.
- Creates the PendingIntent with `FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT` instead of
  `FLAG_MUTABLE` — Android itself rejects a non-empty fill-in `Intent` overriding
  action/data/component on an immutable PendingIntent (blocks Attack A at the platform
  level).
- Sends the leak broadcast via `sendBroadcast(leak, PERMISSION_RECEIVE_PI_LEAK)` instead
  of the bare `sendBroadcast(leak)` — the OS checks the receiving app's signature against
  the permission's declaring app *at delivery time*, before `onReceive()` is ever called.

**MalwareAppV2** (`com.research.pimalwarev2`, signed with `build/malware_v2.keystore`,
**deliberately different** cert, CN=`Malware V2 Attacker`):
- Declares `<uses-permission android:name="com.research.pivictimhardened.permission.RECEIVE_PI_LEAK" />`
  and a receiver with a matching intent-filter for VictimAppHardened's leak action —
  exactly what a real attacker would do after reverse-engineering the wire contract.
- Runs the identical Attack A/B/C logic as MalwareApp, retargeted at VictimAppHardened.

**Verified at build time** (no device needed for these checks):
```
apksigner verify --print-certs dist\pivictimhardened.apk
  → Signer #1 certificate DN: CN=Android Debug, ...        SHA-256: ec26c9ed...
apksigner verify --print-certs dist\pimalwarev2.apk
  → Signer #1 certificate DN: CN=Malware V2 Attacker, ...  SHA-256: 8504e94f...
```
Confirmed different certificates — the precondition for the signature-permission gate to
have anything to enforce.
```
aapt dump xmltree dist\pivictimhardened.apk AndroidManifest.xml | findstr permission
  → E: permission (line=39)
      A: android:name="com.research.pivictimhardened.permission.RECEIVE_PI_LEAK"
      A: android:protectionLevel=(type 0x11)0x2      <- 0x2 = signature
```
Confirmed the permission is declared with `protectionLevel=signature` in the compiled
manifest, not just the source XML.

### Actual on-device result (verified — run on a Pixel 6 AVD, API 30, x86_64)

```powershell
adb install -r dist\pivictimhardened.apk
adb install -r dist\pimalwarev2.apk
adb shell am start -n com.research.pimalwarev2/.MainActivity
adb logcat -s PIVictimHardened:I PIMalwareV2:I PIMalwareV2:W BroadcastQueue:W -v time
```

**Result: the leak broadcast was blocked by the OS before delivery. No capture, no attacks.**

```
I/PIVictimHardened: Created IMMUTABLE PendingIntent: ... creatorPackage=com.research.pivictimhardened creatorUid=10169
I/PIVictimHardened: Sent signature-permission-gated broadcast action=com.research.pivictimhardened.PI_LEAK_ACTION requiredPermission=com.research.pivictimhardened.permission.RECEIVE_PI_LEAK
W/BroadcastQueue: Permission Denial: receiving Intent { act=com.research.pivictimhardened.PI_LEAK_ACTION ... }
    to ProcessRecord{... com.research.pimalwarev2/u0a170} (pid=4956, uid=10170)
    requires com.research.pivictimhardened.permission.RECEIVE_PI_LEAK
    due to sender com.research.pivictimhardened (uid 10169)
W/BroadcastQueue: Permission Denial: receiving Intent { act=com.research.pivictimhardened.PI_LEAK_ACTION ... }
    to com.research.pimalwarev2/.PiCaptureReceiver
    requires com.research.pivictimhardened.permission.RECEIVE_PI_LEAK
    due to sender com.research.pivictimhardened (uid 10169)
```

- **No `PIMalwareV2` log line appears at all** — `PiCaptureReceiver.onReceive()` never ran,
  for either the manifest-declared receiver or the dynamically-registered one added to
  work around Android 8+ background execution limits. ActivityManager's `BroadcastQueue`
  rejected delivery to both at the permission check, before either receiver was invoked.
- `PIVictimHardened`'s own `SensitiveActionReceiver` never fired with attack data (or at
  all) during this run — confirmed by its logcat tag showing only the two creation/leak
  lines above, nothing else.
- This is the real cross-app, cross-UID confirmation that the signature-permission gate
  works as designed: `com.research.pimalwarev2` (uid 10170, signed with a different
  certificate than the victim) was denied receipt by the OS itself, not by any app-level
  logic.

### For comparison — the unprotected baseline, run in the same session

```
I/PIVictim: Created mutable PendingIntent: ... creatorPackage=com.research.pivictim creatorUid=10167
I/PIVictim: Leaked PendingIntent via broadcast action=com.research.pivictim.PI_LEAK_ACTION
I/PIMalware: PI_CAPTURED pendingIntent=... creatorPackage=com.research.pivictim creatorUid=10167 thisPackage=com.research.pimalware thisUid=10168
I/PIMalware: {"attack":"A_fillin_injection","status":"EXECUTED"}
I/PIMalware: {"attack":"B_privilege_escalation","status":"EXECUTED"}
I/PIMalware: {"attack":"C_cancel_hijack","status":"SECURITY_EXCEPTION","detail":"java.lang.SecurityException: Permission Denial: cancelIntentSender() from pid=4873, uid=10168 is not allowed to cancel package com.research.pivictim"}
I/PIVictim: SensitiveActionReceiver fired: EXECUTED ... attackExtra=A_fillin_injection_from_pimalware ...   <- proves cross-app fill-in injection succeeded
I/PIVictim: SensitiveActionReceiver fired: EXECUTED ... attackExtra=null ...                                <- proves cross-app replay succeeded
```

**Unexpected finding, corrected from the original plan:** Attack C (`cancel()` ownership
hijack) was **not** exploitable even in the unprotected baseline. Android's own
`ActivityManagerService.cancelIntentSender()` already checks the caller's UID against the
PendingIntent's owning package and throws `SecurityException` for a mismatch —
independent of `FLAG_MUTABLE`/`FLAG_IMMUTABLE` and independent of any broadcast
permission. This means `.cancel()` ownership hijacking is already prevented by the
platform on this Android version (API 30) for a non-creator process, regardless of the
mitigations tested here. Attacks A (fill-in injection) and B (send() privilege
escalation) **did** succeed unprotected and **were** blocked by the hardened variant —
those are the two attacks the `FLAG_IMMUTABLE` + signature-permission mitigations
actually needed to address, and did.

### Summary table (real logcat evidence, not projected)

| Attack | Baseline (pivictim / pimalware) | Hardened (pivictimhardened / pimalwarev2) |
|---|---|---|
| A — fill-in injection | EXECUTED (reached victim's receiver with attacker's extra) | Never reached — broadcast denied by OS before delivery |
| B — send() escalation | EXECUTED (replayed victim's action) | Never reached — broadcast denied by OS before delivery |
| C — cancel() hijack | SECURITY_EXCEPTION (Android's own UID check on cancelIntentSender, unrelated to this test's mitigations) | N/A — no capture occurred at all |
