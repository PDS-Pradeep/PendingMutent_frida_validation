package com.research.pivictim;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/**
 * VictimApp MainActivity - research/test fixture.
 *
 * On launch:
 *   1. Builds an Intent targeting SensitiveActionReceiver (the "privileged
 *      operation" under test).
 *   2. Wraps it in a MUTABLE PendingIntent (FLAG_MUTABLE, no
 *      FLAG_IMMUTABLE) - the same pattern flagged as a v1 candidate by
 *      analyze_pendingintent_corpus.py.
 *   3. Leaks that PendingIntent to any listener via an unprotected,
 *      exported broadcast (PI_LEAK_ACTION) with no permission - the same
 *      pattern flagged as a v2/v3 exposure risk.
 *
 * This guarantees a real PendingIntent is created and captured by a
 * genuinely separate app/UID every run, unlike scanning pre-existing
 * F-Droid APKs where creation depends on hard-to-trigger UI paths.
 */
public class MainActivity extends Activity {

    private static final String TAG = "PIVictim";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView tv = new TextView(this);
        tv.setText("PI Victim (research)\nCreating + leaking PendingIntent...");
        setContentView(tv);

        Intent sensitiveIntent = new Intent(this, SensitiveActionReceiver.class);
        sensitiveIntent.setAction(SensitiveActionReceiver.SENSITIVE_ACTION);

        // FLAG_MUTABLE (0x02000000) has no named constant before API 31 -
        // before API 31, PendingIntents were mutable by default with no
        // flag needed at all. Using the documented raw bit value keeps
        // this buildable/runnable against API 23-30 while still being the
        // exact same bit FLAG_MUTABLE represents on API 31+.
        final int FLAG_MUTABLE = 0x02000000;
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | FLAG_MUTABLE;

        PendingIntent pendingIntent = PendingIntent.getBroadcast(
                this,
                1001,
                sensitiveIntent,
                flags
        );

        Log.i(TAG, "Created mutable PendingIntent: " + pendingIntent
                + " creatorPackage=" + pendingIntent.getCreatorPackage()
                + " creatorUid=" + pendingIntent.getCreatorUid());

        Intent leak = new Intent(Victim.PI_LEAK_ACTION);
        leak.putExtra(Victim.EXTRA_LEAKED_PI, pendingIntent);
        // setPackage intentionally omitted: this broadcast is unprotected
        // and unaddressed, matching the real-world "leaked to whoever is
        // listening" scenario under test.
        sendBroadcast(leak);

        Log.i(TAG, "Leaked PendingIntent via broadcast action=" + Victim.PI_LEAK_ACTION);
        tv.setText("PI Victim (research)\nPendingIntent created + leaked.\nSee logcat tag PIVictim.");
    }
}
