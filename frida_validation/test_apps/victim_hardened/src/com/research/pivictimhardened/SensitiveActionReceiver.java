package com.research.pivictimhardened;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;

/**
 * VictimAppHardened's "privileged operation" - identical body to the
 * original VictimApp's SensitiveActionReceiver. It still has NO ownership
 * check of its own, and still cannot distinguish who called .send()/
 * .cancel() on the PendingIntent (see README.md for why that check would
 * not work here). It doesn't need to: the two real mitigations
 * (FLAG_IMMUTABLE + signature-permission-gated broadcast) applied upstream
 * in MainActivity are what prevent MalwareApp from ever reaching this
 * receiver with a redirected or replayed action in the first place.
 */
public class SensitiveActionReceiver extends BroadcastReceiver {

    private static final String TAG = "PIVictimHardened";

    public static final String SENSITIVE_ACTION = "com.research.pivictimhardened.SENSITIVE_ACTION";

    @Override
    public void onReceive(Context context, Intent intent) {
        String attackExtra = intent.getStringExtra("attack");
        long now = System.currentTimeMillis();

        String line = "EXECUTED at=" + now
                + " action=" + intent.getAction()
                + " attackExtra=" + attackExtra;

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
