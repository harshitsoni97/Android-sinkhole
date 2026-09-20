package com.sinkhole.adblock.tile

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import com.sinkhole.adblock.R
import com.sinkhole.adblock.ui.MainActivity
import com.sinkhole.adblock.vpn.SinkholeVpnService

/**
 * Lets protection be toggled from the Quick Settings shade (the panel with
 * Wi-Fi/Bluetooth tiles), not just from the app or its notification.
 *
 * VPN consent can only be granted through an Activity, so if it hasn't been
 * granted yet, tapping the tile opens the app instead of trying to start the
 * VPN directly.
 */
class SinkholeTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        refreshTile()
    }

    override fun onClick() {
        super.onClick()
        if (SinkholeVpnService.isRunning.get()) {
            startService(
                Intent(this, SinkholeVpnService::class.java).setAction(SinkholeVpnService.ACTION_STOP)
            )
            refreshTile()
            return
        }

        if (VpnService.prepare(this) != null) {
            openAppForConsent()
            return
        }

        val startIntent = Intent(this, SinkholeVpnService::class.java)
            .setAction(SinkholeVpnService.ACTION_START)
        ContextCompat.startForegroundService(this, startIntent)
        refreshTile()
    }

    private fun openAppForConsent() {
        val appIntent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pendingIntent = PendingIntent.getActivity(
                this, 0, appIntent, PendingIntent.FLAG_IMMUTABLE,
            )
            startActivityAndCollapse(pendingIntent)
        } else {
            @Suppress("DEPRECATION", "StartActivityAndCollapseDeprecated")
            startActivityAndCollapse(appIntent)
        }
    }

    private fun refreshTile() {
        val running = SinkholeVpnService.isRunning.get()
        qsTile?.let { tile ->
            tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            tile.label = getString(R.string.app_name)
            tile.icon = Icon.createWithResource(
                this,
                if (running) R.drawable.ic_shield_on else R.drawable.ic_shield_off,
            )
            tile.updateTile()
        }
    }
}
