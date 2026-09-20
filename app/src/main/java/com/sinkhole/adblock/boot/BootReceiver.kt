package com.sinkhole.adblock.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import com.sinkhole.adblock.data.PrefsManager
import com.sinkhole.adblock.vpn.SinkholeVpnService

/**
 * Restarts protection after a reboot if it was on before the device
 * shut down and VPN consent had already been granted (VpnService.prepare()
 * returning null means the app is already the trusted VPN provider).
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        val prefs = PrefsManager(context)
        if (!prefs.protectionEnabled) return
        if (VpnService.prepare(context) != null) return // consent not (still) granted

        val startIntent = Intent(context, SinkholeVpnService::class.java)
            .setAction(SinkholeVpnService.ACTION_START)
        ContextCompat.startForegroundService(context, startIntent)
    }
}
