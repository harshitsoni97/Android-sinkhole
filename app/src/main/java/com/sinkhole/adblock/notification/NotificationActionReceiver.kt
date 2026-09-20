package com.sinkhole.adblock.notification

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.sinkhole.adblock.vpn.SinkholeVpnService

/**
 * Handles the "Turn On" / "Turn Off" action button on the status
 * notification, letting the user flip protection without opening the app.
 */
class NotificationActionReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_TOGGLE) return

        if (SinkholeVpnService.isRunning.get()) {
            context.startService(
                Intent(context, SinkholeVpnService::class.java).setAction(SinkholeVpnService.ACTION_STOP)
            )
        } else {
            // VPN consent must already have been granted once via MainActivity;
            // once granted, the service can be (re)started directly like this.
            val startIntent = Intent(context, SinkholeVpnService::class.java)
                .setAction(SinkholeVpnService.ACTION_START)
            ContextCompat.startForegroundService(context, startIntent)
        }
    }

    companion object {
        const val ACTION_TOGGLE = "com.sinkhole.adblock.action.TOGGLE"
    }
}
