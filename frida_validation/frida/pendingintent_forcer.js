'use strict';

/*
 * ==========================================================
 * PendingIntent Forcer (deterministic trigger via reflection)
 * ==========================================================
 *
 * Purpose
 * -------
 * Companion to pendingintent_attack_sim.js, addressing a limitation of
 * the original passive/UI-driven harness (run_validation.py's
 * drive_app()): several selected candidates either (a) never invoked a
 * PendingIntent factory during the observation window at all
 * ("NO_DATA"), or (b) only hit a FLAG_NO_CREATE existence-check call
 * that legitimately returns null ("NULL_PENDING_INTENT"), because the
 * real creation call sits behind a specific app-internal method that
 * generic monkey/broadcast driving did not reach.
 *
 * Rather than writing bespoke per-app UI automation (which does not
 * scale and is brittle across app versions), this script uses Frida's
 * Java.choose() + reflective invocation to directly call the exact
 * caller method already identified by static analysis
 * (analyze_pendingintent_corpus.py's analysis.jsonl "caller" field) once
 * the app process is alive - forcing execution of the precise code path
 * that creates the PendingIntent, independent of whether the UI can be
 * driven to reach it.
 *
 * This is intentionally more invasive than UI automation (it calls
 * package-internal, non-public methods via reflection) and is used only
 * as a research/triage tool to obtain a real PendingIntent capture for
 * static-analysis-flagged call sites - it does not simulate a real
 * user or a real external trigger (e.g. a widget update or job
 * scheduler tick). Findings obtained this way should be read as "this
 * call site does create/return a capturable PendingIntent when
 * reached", not as evidence that an unprivileged third party can
 * reliably reach it through normal usage.
 *
 * Configuration
 * -------------
 * Pass the target class name and method name (as reported by
 * analysis.jsonl, converting the smali-style class name
 * "Lcom/pkg/Foo;" to the Java form "com.pkg.Foo") via Frida's
 * --runtime-parameters or by editing FORCE_TARGETS below before
 * loading. Each entry attempts one or more invocation strategies:
 *   1. Zero-arg or all-null-arg reflective call on any live instance of
 *      the class found via Java.choose().
 *   2. If the class exposes a static method with the given name, call
 *      it directly without needing an instance.
 * Failures are logged, not fatal - some methods require real non-null
 * arguments (Context, specific IDs) that cannot be safely synthesized;
 * those are left for manual follow-up and reported as FORCE_ATTEMPT
 * FAILED so the operator knows which call sites still need bespoke
 * triggering (e.g. a real Context obtained from the app's own
 * Application instance, used for methods requiring one).
 *
 * Usage
 * -----
 *   frida -D <serial> -f <package.name> -l pendingintent_forcer.js -l
 *   pendingintent_attack_sim.js -q -t <seconds>
 *
 * (loaded alongside pendingintent_attack_sim.js so any PendingIntent
 * produced as a side effect of the forced call is captured and attacked
 * exactly as it would be for an organically-reached call site.)
 */

// Map of package name -> list of {className, methodName, argCount}
// derived directly from analysis.jsonl "caller" entries for the 8
// previously-unresolved candidates. Methods requiring a real Context/
// complex object argument are marked needsContext:true and are invoked
// with the app's own Application context substituted for the first
// Context-typed parameter (a legitimate value from the target app
// itself, not a synthetic one) - the same identity the app would use if
// it reached the call organically. Other non-primitive args are passed
// as null; if this throws, the failure is a NullPointerException, not a
// PendingIntent-visible outcome, and is logged as FORCE_ATTEMPT FAILED.
var FORCE_TARGETS = {
    "dev.ukanth.ufirewall": [
        { className: "dev.ukanth.ufirewall.widget.ToggleWidget", methodName: "onUpdate", needsContext: true, extraArgCount: 2 },
        { className: "dev.ukanth.ufirewall.widget.StatusWidget", methodName: "showSuccessState", needsContext: true, extraArgCount: 3 },
        { className: "dev.ukanth.ufirewall.Api", methodName: "updateNotification", needsContext: true, extraArgCount: 1, contextIsLastArg: true }
    ],
    "com.acutis.firewall": [
        { className: "com.acutis.firewall.service.FirewallVpnService", methodName: "createNotification", needsContext: false, extraArgCount: 0 }
    ],
    "com.tughi.aggregator": [
        // Kotlin coroutine continuation object; direct reflective call is
        // unlikely to succeed without a live coroutine scope. Recorded
        // here for completeness but expected to require manual triggering
        // (e.g. adb shell cmd jobscheduler run against its refresh job) -
        // see README notes for this package.
        { className: "com.tughi.aggregator.Notifications$refreshNewEntriesNotification$1$1", methodName: "invokeSuspend", needsContext: false, extraArgCount: 1 }
    ],
    "com.pedronveloso.a11ybutton": [
        { className: "com.pedronveloso.a11ybutton.work.ServiceCheckWorker", methodName: "c", needsContext: false, extraArgCount: 1 }
    ],
    "host.stjin.anonaddy": [
        { className: "host.stjin.anonaddy.notifications.NotificationHelper", methodName: "buildSetupAppFirstNotification", needsContext: false, extraArgCount: 2 },
        { className: "host.stjin.anonaddy.notifications.NotificationHelper", methodName: "buildFailedBackupNotification", needsContext: false, extraArgCount: 2 }
    ],
    "com.adguard.android.contentblocker": [
        { className: "com.adguard.android.contentblocker.service.NotificationServiceImpl", methodName: "showRateAppNotification", needsContext: false, extraArgCount: 1 }
    ],
    "com.newoether.agora": [
        { className: "com.newoether.agora.service.AgoraForegroundService$Companion", methodName: "createPendingIntent", needsContext: true, extraArgCount: 1 },
        { className: "com.newoether.agora.data.AutoBackupManager", methodName: "sendFailureNotification", needsContext: false, extraArgCount: 1 }
    ]
};

Java.perform(function () {

    console.log("[+] PendingIntent Forcer active, pid=" + Process.id);

    function logEvent(type, data) {
        console.log(JSON.stringify({
            timestamp: new Date().toISOString(),
            pid: Process.id,
            event: type,
            data: data
        }));
    }

    function getAppContext() {
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var app = ActivityThread.currentApplication();
            return app ? app.getApplicationContext() : null;
        } catch (e) {
            return null;
        }
    }

    function buildArgs(methodDecl, target, appContext) {
        // methodDecl is a specific Frida overload descriptor from
        // .overloads; argumentTypes gives the number/type of parameters.
        var args = [];
        var types = methodDecl.argumentTypes;
        var contextUsed = false;
        for (var i = 0; i < types.length; i++) {
            var t = types[i];
            if (!contextUsed && appContext && t.className &&
                (t.className === "android.content.Context" ||
                 t.className === "android.app.Application")) {
                args.push(appContext);
                contextUsed = true;
            } else if (t.className === "int" || t.className === "long" ||
                       t.className === "short" || t.className === "byte") {
                args.push(0);
            } else if (t.className === "boolean") {
                args.push(false);
            } else if (t.className === "[I") {
                // int[] - AppWidgetProvider.onUpdate's appWidgetIds param.
                // Use an empty array rather than null: many widget
                // handlers iterate this array, and an empty array avoids
                // both a NullPointerException on iteration AND a real
                // (non-existent) widget lookup that would itself throw.
                args.push([]);
            } else {
                args.push(null);
            }
        }
        return args;
    }

    function tryForce(pkg, spec) {
        var attemptedAny = false;
        try {
            var Cls = Java.use(spec.className);
        } catch (e) {
            logEvent("FORCE_ATTEMPT", {
                package: pkg, className: spec.className, methodName: spec.methodName,
                status: "CLASS_NOT_FOUND", detail: String(e)
            });
            return;
        }

        var appContext = getAppContext();

        // Strategy 1: static method, no instance needed. Frida's
        // Java.use() wrapper exposes BOTH static and instance methods as
        // properties of the class object, so we must explicitly check
        // isStatic per overload rather than assuming presence on Cls
        // means "callable with Cls as receiver" - calling an instance
        // method with the class object as `this` throws "expected a
        // pointer" (an invalid native `this`), which previously masked
        // the fact that Strategy 1 does not apply to this method at all
        // and prevented Strategy 2/3 (instance-based) from running.
        try {
            var m = Cls[spec.methodName];
            if (m && m.overloads && m.overloads.length > 0) {
                var anyStatic = false;
                m.overloads.forEach(function (ov) {
                    if (!ov.isStatic) return;
                    anyStatic = true;
                    attemptedAny = true;
                    try {
                        var args = buildArgs(ov, null, appContext);
                        ov.apply(Cls, args);
                        logEvent("FORCE_ATTEMPT", {
                            package: pkg, className: spec.className, methodName: spec.methodName,
                            status: "STATIC_CALL_OK", argCount: args.length
                        });
                    } catch (callErr) {
                        logEvent("FORCE_ATTEMPT", {
                            package: pkg, className: spec.className, methodName: spec.methodName,
                            status: "STATIC_CALL_FAILED", detail: String(callErr)
                        });
                    }
                });
                if (!anyStatic) {
                    // All overloads are instance methods - explicitly
                    // fall through to Strategy 2/3 below instead of
                    // silently having "attempted" a call that could
                    // never have succeeded.
                }
            }
        } catch (staticErr) {
            // Not directly introspectable on the class object - fall
            // through to instance-based invocation below.
        }

        // Strategy 2: find a live instance via Java.choose() and invoke
        // the (possibly non-static/private) method reflectively on it.
        var foundLiveInstance = false;
        try {
            Java.choose(spec.className, {
                onMatch: function (instance) {
                    attemptedAny = true;
                    foundLiveInstance = true;
                    invokeOnInstance(pkg, spec, instance, appContext, "INSTANCE_CALL");
                },
                onComplete: function () {}
            });
        } catch (chooseErr) {
            logEvent("FORCE_ATTEMPT", {
                package: pkg, className: spec.className, methodName: spec.methodName,
                status: "CHOOSE_FAILED", detail: String(chooseErr)
            });
        }

        // Strategy 3: no live instance exists (e.g. an Android
        // Service/Receiver/Activity that Android has not yet
        // instantiated because its normal lifecycle trigger - a real
        // VpnService.prepare() consent flow, an actual widget placement,
        // an actual coroutine dispatch - never fired). Allocate a bare
        // instance directly via $new()/$alloc() and invoke the target
        // method on it. This bypasses the component's Android lifecycle
        // entirely (no onCreate()/onBind() semantics), which is why it is
        // attempted only as a fallback: it can produce a PendingIntent
        // capture even when the component was never properly started,
        // but any code in the method that depends on lifecycle state
        // (e.g. a VpnService's underlying tun interface) may throw - that
        // failure is logged, not fatal, and does not indicate the
        // PendingIntent-creating line itself is unreachable in the real
        // component lifecycle.
        if (!foundLiveInstance && !spec.skipBareAlloc) {
            // Strategy 3a: real construction. Try every declared
            // constructor overload, substituting the app's real, live
            // Application context for any Context/Application-typed
            // parameter and null for everything else. This handles the
            // common case of a plain class holding a Context in a
            // constructor-set field (e.g. `class Foo(private val
            // context: Context)`), which $alloc() cannot populate since
            // it skips the constructor entirely.
            var constructed = false;
            try {
                var ctors = Cls.$init ? Cls.$init.overloads : [];
                for (var ci = 0; ci < ctors.length && !constructed; ci++) {
                    try {
                        var ctorArgs = buildArgs(ctors[ci], null, appContext);
                        var inst = Cls.$new.apply(Cls, ctorArgs);
                        attemptedAny = true;
                        constructed = true;
                        invokeOnInstance(pkg, spec, inst, appContext, "REAL_CTOR_CALL");
                    } catch (ctorErr) {
                        // try next overload
                    }
                }
            } catch (introErr) {
                // $init not introspectable this way - fall through to
                // bare alloc below.
            }

            // Strategy 3b: bare $alloc() + best-effort attachBaseContext
            // for ContextWrapper descendants (Service/Activity/etc.),
            // used only if real construction (3a) did not succeed.
            if (!constructed) {
                try {
                    var instance;
                    try {
                        instance = Cls.$alloc ? Cls.$alloc() : Cls.$new();
                    } catch (allocErr) {
                        instance = Cls.$new();
                    }

                    try {
                        var isContextWrapper = false;
                        try {
                            var sc = instance.class;
                            while (sc) {
                                if (sc.getName() === "android.content.ContextWrapper") { isContextWrapper = true; break; }
                                sc = sc.getSuperclass();
                            }
                        } catch (introErr2) {
                            isContextWrapper = false;
                        }
                        if (isContextWrapper && appContext) {
                            var wrapper = Java.cast(instance, Java.use("android.content.ContextWrapper"));
                            wrapper.attachBaseContext(appContext);
                        }
                    } catch (attachErr) {
                        // Not attachable this way - proceed anyway; the
                        // target call below will surface its own error.
                    }

                    attemptedAny = true;
                    invokeOnInstance(pkg, spec, instance, appContext, "BARE_ALLOC_CALL");
                } catch (allocErr2) {
                    logEvent("FORCE_ATTEMPT", {
                        package: pkg, className: spec.className, methodName: spec.methodName,
                        status: "BARE_ALLOC_FAILED", detail: String(allocErr2)
                    });
                }
            }
        }

        if (!attemptedAny) {
            logEvent("FORCE_ATTEMPT", {
                package: pkg, className: spec.className, methodName: spec.methodName,
                status: "NO_LIVE_INSTANCE_AND_NOT_STATIC",
                detail: "no instance found via Java.choose() within this window, and method is not static"
            });
        }
    }

    function invokeOnInstance(pkg, spec, instance, appContext, statusPrefix) {
        try {
            var m = instance[spec.methodName];
            if (m && m.overloads && m.overloads.length > 0) {
                m.overloads.forEach(function (ov) {
                    try {
                        var args = buildArgs(ov, instance, appContext);
                        ov.apply(instance, args);
                        logEvent("FORCE_ATTEMPT", {
                            package: pkg, className: spec.className, methodName: spec.methodName,
                            status: statusPrefix + "_OK", argCount: args.length
                        });
                    } catch (callErr) {
                        logEvent("FORCE_ATTEMPT", {
                            package: pkg, className: spec.className, methodName: spec.methodName,
                            status: statusPrefix + "_FAILED", detail: String(callErr)
                        });
                    }
                });
            }
        } catch (e) {
            logEvent("FORCE_ATTEMPT", {
                package: pkg, className: spec.className, methodName: spec.methodName,
                status: statusPrefix.replace("CALL", "INTROSPECTION") + "_FAILED", detail: String(e)
            });
        }
    }

    // Resolve current package name from the process itself, then run
    // every configured force target for it after a short settle delay
    // (mirrors drive_app()'s 2s post-spawn wait in run_validation.py).
    setTimeout(function () {
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var app = ActivityThread.currentApplication();
            var pkg = app ? app.getPackageName() : null;

            if (!pkg || !FORCE_TARGETS[pkg]) {
                logEvent("FORCER_INFO", { detail: "no FORCE_TARGETS configured for package=" + pkg });
                return;
            }

            logEvent("FORCER_INFO", { detail: "forcing " + FORCE_TARGETS[pkg].length + " call site(s) for " + pkg });
            FORCE_TARGETS[pkg].forEach(function (spec) {
                tryForce(pkg, spec);
            });
        } catch (e) {
            logEvent("FORCER_ERROR", { detail: String(e) });
        }
    }, 2500);
});
