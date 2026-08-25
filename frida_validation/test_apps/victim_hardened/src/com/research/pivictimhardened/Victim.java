package com.research.pivictimhardened;

/**
 * Shared constants for VictimAppHardened.
 */
public final class Victim {

    private Victim() {}

    /** Broadcast action used to deliver the PendingIntent - now gated by a
     *  signature-level permission (see AndroidManifest.xml), unlike the
     *  unprotected VictimApp original. */
    public static final String PI_LEAK_ACTION = "com.research.pivictimhardened.PI_LEAK_ACTION";

    /** Extra key under which the (now immutable) PendingIntent is attached. */
    public static final String EXTRA_LEAKED_PI = "leaked_pi";

    /** Signature-level permission required to receive PI_LEAK_ACTION. Only
     *  apps signed with the same certificate as this APK can ever hold it. */
    public static final String PERMISSION_RECEIVE_PI_LEAK =
            "com.research.pivictimhardened.permission.RECEIVE_PI_LEAK";
}
