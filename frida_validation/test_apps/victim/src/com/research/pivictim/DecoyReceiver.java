package com.research.pivictim;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * Represents an unrelated, benign component inside VictimApp - used only
 * as a redirection TARGET for Attack E (disruption via redirect). It is
 * not itself sensitive; its only purpose is to prove that a fill-in
 * Intent's setComponent() can steer the delegated dispatch completely
 * away from SensitiveActionReceiver, so the creator's intended action
 * silently never fires while the attacker's chosen component runs
 * instead - a disruption/neutralization outcome distinct from Attack A's
 * data-injection framing.
 */
public class DecoyReceiver extends BroadcastReceiver {

    private static final String TAG = "PIVictim";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(TAG, "DecoyReceiver fired instead of SensitiveActionReceiver - "
                + "redirect disruption succeeded. action=" + intent.getAction());
    }
}
