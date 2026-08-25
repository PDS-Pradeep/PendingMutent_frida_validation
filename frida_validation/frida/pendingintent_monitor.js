'use strict';

Java.perform(function () {

    console.log("==========================================");
    console.log("[+] PendingIntent Runtime Monitor");
    console.log("[+] Target process: " + Process.id);
    console.log("==========================================");

    var PendingIntent = Java.use("android.app.PendingIntent");
    var Intent = Java.use("android.content.Intent");

    /*
     * ---------------------------------------------------------
     * Helper functions
     * ---------------------------------------------------------
     */

    function intentInfo(intent) {

        if (intent === null || intent === undefined) {
            return "Intent=null";
        }

        var result = [];

        try {
            result.push("action=" + intent.getAction());
        } catch (e) {}

        try {
            result.push("component=" + intent.getComponent());
        } catch (e) {}

        try {
            result.push("package=" + intent.getPackage());
        } catch (e) {}

        try {
            result.push("data=" + intent.getDataString());
        } catch (e) {}

        try {
            result.push("flags=0x" + intent.getFlags().toString(16));
        } catch (e) {}

        try {
            result.push("categories=" + intent.getCategories());
        } catch (e) {}

        try {
            var extras = intent.getExtras();

            if (extras !== null) {
                result.push("extras=" + extras.toString());
            }
        } catch (e) {}

        return result.join(" | ");
    }


    function pendingIntentInfo(pi) {

        if (pi === null || pi === undefined) {
            return "PendingIntent=null";
        }

        var result = [];

        try {
            result.push("creatorPackage=" + pi.getCreatorPackage());
        } catch (e) {}

        try {
            result.push("creatorUid=" + pi.getCreatorUid());
        } catch (e) {}

        try {
            result.push("creatorUserHandle=" + pi.getCreatorUserHandle());
        } catch (e) {}

        try {
            result.push("targetPackage=" + pi.getTargetPackage());
        } catch (e) {}

        return result.join(" | ");
    }


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


    /*
     * ---------------------------------------------------------
     * PendingIntent creation
     * ---------------------------------------------------------
     */

    function hookCreation(methodName) {

        try {

            var overloads = PendingIntent[methodName].overloads;

            overloads.forEach(function (ov) {

                ov.implementation = function () {

                    var args = [];

                    for (var i = 0; i < arguments.length; i++) {
                        args.push(arguments[i]);
                    }

                    var flags = null;

                    /*
                     * PendingIntent getXXX normally has flags
                     * as one of its final arguments.
                     */
                    for (var i = args.length - 1; i >= 0; i--) {

                        try {
                            if (typeof args[i] === "number") {
                                flags = args[i];
                                break;
                            }
                        } catch (e) {}
                    }

                    var pi = ov.apply(this, arguments);

                    var flagInfo = {
                        rawFlags: flags
                    };

                    if (flags !== null) {

                        /*
                         * Android PendingIntent flags:
                         *
                         * FLAG_ONE_SHOT   = 0x40000000
                         * FLAG_NO_CREATE  = 0x20000000
                         * FLAG_CANCEL_CURRENT = 0x10000000
                         * FLAG_UPDATE_CURRENT = 0x08000000
                         * FLAG_IMMUTABLE = 0x04000000
                         * FLAG_MUTABLE = 0x02000000
                         */

                        flagInfo.mutable =
                            ((flags & 0x02000000) !== 0);

                        flagInfo.immutable =
                            ((flags & 0x04000000) !== 0);

                        flagInfo.updateCurrent =
                            ((flags & 0x08000000) !== 0);

                        flagInfo.cancelCurrent =
                            ((flags & 0x10000000) !== 0);
                    }

                    logEvent(
                        "PENDING_INTENT_CREATE",
                        {
                            api: methodName,
                            flags: flagInfo,
                            pendingIntent: pendingIntentInfo(pi)
                        }
                    );

                    return pi;
                };
            });

            console.log(
                "[+] Hooked PendingIntent." + methodName
            );

        } catch (e) {

            console.log(
                "[-] Failed to hook " +
                methodName +
                ": " +
                e
            );
        }
    }


    hookCreation("getActivity");
    hookCreation("getActivities");
    hookCreation("getBroadcast");
    hookCreation("getService");
    hookCreation("getForegroundService");


    /*
     * ---------------------------------------------------------
     * PendingIntent.send()
     * ---------------------------------------------------------
     */

    try {

        PendingIntent.send.overloads.forEach(function (ov) {

            ov.implementation = function () {

                var args = [];

                for (var i = 0; i < arguments.length; i++) {
                    args.push(arguments[i]);
                }

                logEvent(
                    "PENDING_INTENT_SEND",
                    {
                        pendingIntent:
                            pendingIntentInfo(this),

                        argumentCount:
                            args.length
                    }
                );

                return ov.apply(this, arguments);
            };

        });

        console.log("[+] Hooked PendingIntent.send()");

    } catch (e) {

        console.log(
            "[-] send hook failed: " + e
        );
    }


    /*
     * ---------------------------------------------------------
     * PendingIntent.cancel()
     * ---------------------------------------------------------
     */

    try {

        PendingIntent.cancel.implementation = function () {

            logEvent(
                "PENDING_INTENT_CANCEL",
                {
                    pendingIntent:
                        pendingIntentInfo(this)
                }
            );

            return this.cancel();

        };

        console.log("[+] Hooked PendingIntent.cancel()");

    } catch (e) {

        console.log(
            "[-] cancel hook failed: " + e
        );
    }


    /*
     * ---------------------------------------------------------
     * PendingIntent.getIntentSender()
     * ---------------------------------------------------------
     */

    try {

        PendingIntent.getIntentSender.implementation = function () {

            logEvent(
                "PENDING_INTENT_GET_INTENT_SENDER",
                {
                    pendingIntent:
                        pendingIntentInfo(this)
                }
            );

            return this.getIntentSender();

        };

        console.log(
            "[+] Hooked PendingIntent.getIntentSender()"
        );

    } catch (e) {

        console.log(
            "[-] getIntentSender hook failed: " + e
        );
    }


    /*
     * ---------------------------------------------------------
     * PendingIntent creator / ownership
     * ---------------------------------------------------------
     */

    try {

        PendingIntent.getCreatorPackage.implementation =
            function () {

                var result =
                    this.getCreatorPackage();

                logEvent(
                    "PENDING_INTENT_CREATOR",
                    {
                        creatorPackage: result
                    }
                );

                return result;
            };

        console.log(
            "[+] Hooked getCreatorPackage()"
        );

    } catch (e) {}


    /*
     * ---------------------------------------------------------
     * Intent.fillIn()
     *
     * Critical for V1.
     * ---------------------------------------------------------
     */

    try {

        Intent.fillIn.overloads.forEach(function (ov) {

            ov.implementation = function () {

                var before = intentInfo(this);

                var result =
                    ov.apply(this, arguments);

                var after = intentInfo(this);

                var flags = null;

                try {
                    flags = arguments[1];
                } catch (e) {}

                logEvent(
                    "INTENT_FILL_IN",
                    {
                        before: before,
                        after: after,
                        fillInFlags: flags
                    }
                );

                return result;
            };

        });

        console.log("[+] Hooked Intent.fillIn()");

    } catch (e) {

        console.log(
            "[-] fillIn hook failed: " + e
        );
    }


    /*
     * ---------------------------------------------------------
     * Intent.setComponent()
     * ---------------------------------------------------------
     */

    try {

        Intent.setComponent.overloads.forEach(function (ov) {

            ov.implementation = function () {

                var result =
                    ov.apply(this, arguments);

                logEvent(
                    "INTENT_SET_COMPONENT",
                    {
                        intent: intentInfo(this)
                    }
                );

                return result;
            };

        });

        console.log("[+] Hooked Intent.setComponent()");

    } catch (e) {}


    /*
     * ---------------------------------------------------------
     * Intent.setPackage()
     * ---------------------------------------------------------
     */

    try {

        Intent.setPackage.overloads.forEach(function (ov) {

            ov.implementation = function () {

                var result =
                    ov.apply(this, arguments);

                logEvent(
                    "INTENT_SET_PACKAGE",
                    {
                        intent: intentInfo(this)
                    }
                );

                return result;
            };

        });

        console.log("[+] Hooked Intent.setPackage()");

    } catch (e) {}


    /*
     * ---------------------------------------------------------
     * Intent.putExtra()
     * ---------------------------------------------------------
     */

    try {

        Intent.putExtra.overloads.forEach(function (ov) {

            ov.implementation = function () {

                var result =
                    ov.apply(this, arguments);

                logEvent(
                    "INTENT_PUT_EXTRA",
                    {
                        intent:
                            intentInfo(this)
                    }
                );

                return result;
            };

        });

        console.log("[+] Hooked Intent.putExtra()");

    } catch (e) {}


    console.log(
        "[+] Runtime instrumentation ready"
    );

});