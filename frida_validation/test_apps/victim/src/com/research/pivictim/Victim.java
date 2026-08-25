package com.research.pivictim;

/**
 * Shared constants for VictimApp. Kept in a small holder class (rather than
 * duplicated string literals) so MainActivity and SensitiveActionReceiver
 * agree on the exact contract, and so the constants are easy to reference
 * from documentation/tooling.
 */
public final class Victim {

    private Victim() {}

    /** Unprotected, exported broadcast action used to leak the PendingIntent. */
    public static final String PI_LEAK_ACTION = "com.research.pivictim.PI_LEAK_ACTION";

    /** Extra key under which the leaked PendingIntent is attached. */
    public static final String EXTRA_LEAKED_PI = "leaked_pi";
}
