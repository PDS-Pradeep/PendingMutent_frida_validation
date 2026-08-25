package com.research.pivictimhardened;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/**
 * VictimAppHardened MainActivity - research/test fixture.
 *
 * Same flow as the original VictimApp, but with both real mitigations
 * applied:
 *
 *   1. PendingIntent.getBroadcast(..., FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT)
 *      instead of FLAG_MUTABLE - Android itself rejects fill-in overrides
 *      of action/data/component on an immutable PendingIntent (Attack A).
 *
 *   2. sendBroadcast(intent, PERMISSION_RECEIVE_PI_LEAK) instead of the
 *      bare sendBroadcast(intent) - only a receiver in a package signed
 *      with VictimAppHardened's own certificate will ever be granted that
 *      signature-level permission and therefore ever get this broadcast
 *      delivered at all (Attacks B and C have nothing to operate on if
 *      the broadcast never arrives).
 */
public class MainActivity extends Activity {

    private static final String TAG = "PIVictimHardened";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView tv = new TextView(this);
        tv.setText("PI Victim Hardened (research)\nCreating immutable PendingIntent + signature-gated leak...");
        setContentView(tv);

        Intent sensitiveIntent = new Intent(this, SensitiveActionReceiver.class);
        sensitiveIntent.setAction(SensitiveActionReceiver.SENSITIVE_ACTION);

        // Mitigation 1: FLAG_IMMUTABLE instead of FLAG_MUTABLE.
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;

        PendingIntent pendingIntent = PendingIntent.getBroadcast(
                this,
                1001,
                sensitiveIntent,
                flags
        );

        Log.i(TAG, "Created IMMUTABLE PendingIntent: " + pendingIntent
                + " creatorPackage=" + pendingIntent.getCreatorPackage()
                + " creatorUid=" + pendingIntent.getCreatorUid());

        Intent leak = new Intent(Victim.PI_LEAK_ACTION);
        leak.putExtra(Victim.EXTRA_LEAKED_PI, pendingIntent);

        // Mitigation 2: signature-level permission required to receive
        // this broadcast at all. Android's PackageManager enforces this at
        // delivery time - a receiver in an app not signed with the same
        // certificate never sees this Intent, regardless of exported=true
        // or matching intent-filters.
        sendBroadcast(leak, Victim.PERMISSION_RECEIVE_PI_LEAK);

        Log.i(TAG, "Sent signature-permission-gated broadcast action=" + Victim.PI_LEAK_ACTION
                + " requiredPermission=" + Victim.PERMISSION_RECEIVE_PI_LEAK);
        tv.setText("PI Victim Hardened (research)\nImmutable PendingIntent created;\nleak broadcast requires signature permission.\nSee logcat tag PIVictimHardened.");
    }
}
