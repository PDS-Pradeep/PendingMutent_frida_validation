'use strict';

/*
 * ==========================================================
 * PendingIntent Defense Simulator ("Phase B" reference gate)
 * ==========================================================
 *
 * Purpose
 * -------
 * Companion to pendingintent_attack_sim.js. That script performs three
 * attacker-style operations (A: fill-in injection, B: privilege
 * escalation via send(), C: cancel() ownership hijack) directly against
 * a captured PendingIntent and records whether Android allows them.
 *
 * This script instead wraps the SAME three operations behind an
 * ownership-authorisation gate before they are allowed to reach the real
 * Android PendingIntent API, and records whether the gate correctly
 * DENIES them. It is a minimal, Frida-injected reference implementation
 * of the ownership-check idea (creator vs. non-creator), NOT a bytecode-
 * embedded replacement library and NOT a claim that any specific paper's
 * formal pipeline (chi/psi/Xi/Pi) is implemented here. Read this as:
 * "if you gate these three operations on creator-package identity, do
 * real captured PendingIntents from real apps get correctly denied?"
 *
 * IMPORTANT LIMITATION - READ BEFORE INTERPRETING RESULTS
 * ---------------------------------------------------------
 * Frida attaches by spawning/hooking the target app's OWN process, so
 * every call this script makes runs inside the creator app's process and
 * UID. There is no real second malicious app/UID in this test. To make
 * the ownership check meaningful anyway, the "invoker" identity for the
 * attack path is a SYNTHETIC label (SIMULATED_MALWARE_PACKAGE below),
 * deliberately distinct from the real creatorPackage reported by
 * Android for the captured PendingIntent (pi.getCreatorPackage(), a
 * genuine value from the OS, not fabricated). Because invoker !=
 * creator by construction, the gate is EXPECTED to deny every attack
 * attempt - that is the property being tested (the DENY branch of the
 * authorisation function, evaluated against real creatorPackage values
 * from 13 real, unmodified APKs), not evidence of a true cross-process
 * security boundary.
 *
 * To also check for false positives without destabilising the running
 * app, this script separately evaluates (as a pure logic check, without
 * calling the real Android API) what the SAME authorisation function
 * returns when invoker == creator (the legitimate, creator-invoked
 * case). This must return ALLOW for the gate to be considered
 * non-disruptive to normal app behaviour.
 *
 * Usage
 * -----
 *   frida -D <serial> -f <package.name> -l pendingintent_defense_sim.js -q -t <seconds>
 *
 * Output is JSON-lines on stdout, same event shape as the attack
 * simulator but with event name "DEFENSE_RESULTS" and status values
 * BLOCKED_BY_POLICY / ALLOWED_BY_POLICY (policy-only, not executed) /
 * NULL_PENDING_INTENT.
 */

var SIMULATED_MALWARE_PACKAGE = "com.malware.simulated";

Java.perform(function () {

    console.log("==========================================");
    console.log("[+] PendingIntent Defense Simulator (reference ownership gate)");
    console.log("[+] Target process: " + Process.id);
    console.log("==========================================");

    var PendingIntent = Java.use("android.app.PendingIntent");

    var handled = {};

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
        try {
            return pi.toString();
        } catch (e) {
            return "unknown-" + Math.random();
        }
    }

    function safeStr(e) {
        try { return e.toString(); } catch (_) { return "unknown error"; }
    }

    /*
     * ---------------------------------------------------------
     * Ownership-authorisation gate.
     *
     * All three operations under test (fill-in redirection, send()-based
     * invocation, cancel()) are treated as ownership-sensitive: only the
     * creator package may perform them. This mirrors the
     * Ownership-Invocation-Separation idea (possession of a PendingIntent
     * reference does not by itself grant management authority over it).
     * ---------------------------------------------------------
     */
    function authorize(creatorPackage, invokerPackage, operation) {
        if (creatorPackage === invokerPackage) {
            return { decision: "ALLOW", reason: "invoker is the creator package" };
        }
        return {
            decision: "DENY",
            reason: "invoker (" + invokerPackage + ") is not the creator (" +
                creatorPackage + ") for ownership-sensitive operation '" + operation + "'"
        };
    }

    /*
     * ---------------------------------------------------------
     * Gated Attack A: fill-in Intent injection
     * ---------------------------------------------------------
     */
    function gatedAttackA(pi, apiName, creatorPackage) {
        var outcome = { attack: "A_fillin_injection", api: apiName };
        var auth = authorize(creatorPackage, SIMULATED_MALWARE_PACKAGE, "fillin_redirect");
        outcome.authorization = auth;

        if (auth.decision === "DENY") {
            outcome.status = "BLOCKED_BY_POLICY";
            outcome.detail = "gate denied fill-in redirection before reaching PendingIntent.send(); " + auth.reason;
            return outcome;
        }

        // Not reached in this evaluation (invoker is always synthetic/non-creator),
        // kept for completeness in case authorize() logic is extended later.
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var context = ActivityThread.currentApplication().getApplicationContext();
            var maliciousIntent = Java.use("android.content.Intent").$new();
            maliciousIntent.setAction("com.malware.ATTACKER_ACTION");
            pi.send(context, 0, maliciousIntent);
            outcome.status = "EXECUTED_NO_EXCEPTION";
            outcome.detail = "gate allowed the call; it reached the real API without exception";
        } catch (e) {
            outcome.status = "EXCEPTION";
            outcome.detail = safeStr(e);
        }
        return outcome;
    }

    /*
     * ---------------------------------------------------------
     * Gated Attack B: privilege escalation via send()
     * ---------------------------------------------------------
     */
    function gatedAttackB(pi, apiName, creatorPackage) {
        var outcome = { attack: "B_privilege_escalation", api: apiName };
        var auth = authorize(creatorPackage, SIMULATED_MALWARE_PACKAGE, "invoke_send");
        outcome.authorization = auth;

        if (auth.decision === "DENY") {
            outcome.status = "BLOCKED_BY_POLICY";
            outcome.detail = "gate denied send() invocation before reaching PendingIntent.send(); " + auth.reason;
            return outcome;
        }

        try {
            pi.send();
            outcome.status = "EXECUTED_NO_EXCEPTION";
            outcome.detail = "gate allowed the call; it reached the real API without exception";
        } catch (e) {
            outcome.status = "EXCEPTION";
            outcome.detail = safeStr(e);
        }
        return outcome;
    }

    /*
     * ---------------------------------------------------------
     * Gated Attack C: cancel() ownership hijack
     * ---------------------------------------------------------
     */
    function gatedAttackC(pi, apiName, creatorPackage) {
        var outcome = { attack: "C_cancel_hijack", api: apiName };
        var auth = authorize(creatorPackage, SIMULATED_MALWARE_PACKAGE, "cancel");
        outcome.authorization = auth;

        if (auth.decision === "DENY") {
            outcome.status = "BLOCKED_BY_POLICY";
            outcome.detail = "gate denied cancel() before reaching PendingIntent.cancel(); " + auth.reason;
            return outcome;
        }

        try {
            pi.cancel();
            outcome.status = "EXECUTED_NO_EXCEPTION";
            outcome.detail = "gate allowed the call; it reached the real API without exception";
        } catch (e) {
            outcome.status = "EXCEPTION";
            outcome.detail = safeStr(e);
        }
        return outcome;
    }

    /*
     * ---------------------------------------------------------
     * False-positive check: policy-only evaluation (no real API call)
     * of the SAME authorize() function when invoker == creator. This
     * must return ALLOW for all three operations, or the gate would
     * disrupt the app's own legitimate use of its PendingIntents.
     * ---------------------------------------------------------
     */
    function falsePositiveCheck(creatorPackage) {
        var ops = ["fillin_redirect", "invoke_send", "cancel"];
        var results = {};
        var allAllowed = true;
        ops.forEach(function (op) {
            var auth = authorize(creatorPackage, creatorPackage, op);
            results[op] = auth.decision;
            if (auth.decision !== "ALLOW") allAllowed = false;
        });
        return { results: results, allAllowed: allAllowed };
    }

    function hookAndGate(methodName) {
        try {
            var overloads = PendingIntent[methodName].overloads;

            overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var pi = ov.apply(this, arguments);

                    try {
                        var k = keyFor(pi);
                        if (!handled[k]) {
                            handled[k] = true;

                            logEvent("PI_CAPTURED", {
                                api: methodName,
                                pendingIntent: pendingIntentInfo(pi)
                            });

                            var results = [];

                            if (pi === null || pi === undefined) {
                                var nullOutcome = { status: "NULL_PENDING_INTENT", detail: "factory returned null - nothing to gate" };
                                results.push({ attack: "A_fillin_injection", api: methodName, status: nullOutcome.status, detail: nullOutcome.detail });
                                results.push({ attack: "B_privilege_escalation", api: methodName, status: nullOutcome.status, detail: nullOutcome.detail });
                                results.push({ attack: "C_cancel_hijack", api: methodName, status: nullOutcome.status, detail: nullOutcome.detail });

                                logEvent("DEFENSE_RESULTS", {
                                    api: methodName,
                                    pendingIntent: "PendingIntent=null",
                                    results: results
                                });
                            } else {
                                var creatorPackage = null;
                                try { creatorPackage = pi.getCreatorPackage(); } catch (e) {}

                                results.push(gatedAttackA(pi, methodName, creatorPackage));
                                results.push(gatedAttackB(pi, methodName, creatorPackage));
                                results.push(gatedAttackC(pi, methodName, creatorPackage));

                                var fpCheck = falsePositiveCheck(creatorPackage);

                                logEvent("DEFENSE_RESULTS", {
                                    api: methodName,
                                    pendingIntent: pendingIntentInfo(pi),
                                    results: results,
                                    falsePositiveCheck: fpCheck
                                });
                            }
                        }
                    } catch (gateErr) {
                        logEvent("DEFENSE_HARNESS_ERROR", {
                            api: methodName,
                            error: safeStr(gateErr)
                        });
                    }

                    return pi;
                };
            });

            console.log("[+] Hooked+gating PendingIntent." + methodName);

        } catch (e) {
            console.log("[-] Failed to hook " + methodName + ": " + e);
        }
    }

    hookAndGate("getActivity");
    hookAndGate("getActivities");
    hookAndGate("getBroadcast");
    hookAndGate("getService");
    hookAndGate("getForegroundService");

    console.log("[+] Defense gate ready - attacks fire and are evaluated against the ownership policy on every PendingIntent creation");
});
