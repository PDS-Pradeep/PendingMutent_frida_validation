package com.research.pivictim;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;

/**
 * VictimApp's "privileged operation" - research/test fixture.
 *
 * Represents whatever sensitive action a real app might gate behind a
 * PendingIntent (e.g. dismissing a notification, completing a payment,
 * granting a permission, replaying an authenticated action). It has NO
 * way to distinguish "the OS delivered this because MainActivity's own
 * PendingIntent.send() was called" from "some other process holding a
 * Binder reference to the PendingIntent called .send() on it" - that
 * ambiguity is exactly the v1/v3 risk under test.
 *
 * android:exported="false" in the manifest only prevents OTHER apps from
 * broadcasting SENSITIVE_ACTION directly; it does NOT prevent another app
 * from triggering this receiver indirectly via PendingIntent.send() on a
 * captured PendingIntent, since the PendingIntent carries the creator
 * app's own authority regardless of who invokes send().
 *
 * Every invocation is recorded to a world-readable-by-this-app marker
 * file (executed.txt in app-internal storage) and to logcat, so a test
 * harness can confirm whether the action fired, and with which extras
 * (proving fill-in injection if Attack A's extras appear here).
 */
public class SensitiveActionReceiver extends BroadcastReceiver {

    private static final String TAG = "PIVictim";

    public static final String SENSITIVE_ACTION = "com.research.pivictim.SENSITIVE_ACTION";

    @Override
    public void onReceive(Context context, Intent intent) {
        String attackExtra = intent.getStringExtra("attack");
        long now = System.currentTimeMillis();

        String line = "EXECUTED at=" + now
                + " action=" + intent.getAction()
                + " attackExtra=" + attackExtra
                + " callingPkgUnavailable=true";

        Log.i(TAG, "SensitiveActionReceiver fired: " + line);

        try {
            FileOutputStream fos = context.openFileOutput("executed.txt", Context.MODE_APPEND);
            Writer w = new OutputStreamWriter(fos);
            w.write(line);
            w.write("\n");
            w.flush();
            w.close();
        } catch (IOException e) {
            Log.e(TAG, "Failed writing executed.txt", e);
        }
    }
}
