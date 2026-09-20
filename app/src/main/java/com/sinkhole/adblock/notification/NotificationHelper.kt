package com.sinkhole.adblock.notification

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.sinkhole.adblock.R
import com.sinkhole.adblock.data.PrefsManager
import com.sinkhole.adblock.ui.MainActivity

/** Builds/updates the single persistent status notification for the VPN service. */
object NotificationHelper {

    const val CHANNEL_ID = "sinkhole_status"
    const val CHANNEL_ID_MINIMAL = "sinkhole_status_min"
    const val NOTIFICATION_ID = 1

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    context.getString(R.string.notification_channel_name),
                    NotificationManager.IMPORTANCE_LOW,
                ).apply {
                    description = context.getString(R.string.notification_channel_description)
                    setShowBadge(false)
                }
            )
        }
        if (manager.getNotificationChannel(CHANNEL_ID_MINIMAL) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID_MINIMAL,
                    context.getString(R.string.notification_channel_name_minimal),
                    NotificationManager.IMPORTANCE_MIN,
                ).apply {
                    description = context.getString(R.string.notification_channel_description)
                    setShowBadge(false)
                }
            )
        }
    }

    /** [running] reflects whether the VPN tunnel is currently up. */
    fun buildStatusNotification(
        context: Context,
        running: Boolean,
        blockedCount: Long,
    ): android.app.Notification {
        ensureChannel(context)

        val minimal = PrefsManager(context).minimalNotification

        val contentIntent = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val title = if (running) {
            context.getString(R.string.notification_title_active)
        } else {
            context.getString(R.string.notification_title_inactive)
        }
        val text = if (running) {
            context.getString(R.string.notification_text_blocked_count, blockedCount)
        } else {
            context.getString(R.string.notification_text_inactive)
        }

        val builder = NotificationCompat.Builder(
            context,
            if (minimal) CHANNEL_ID_MINIMAL else CHANNEL_ID,
        )
            .setSmallIcon(if (running) R.drawable.ic_shield_on else R.drawable.ic_shield_off)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(contentIntent)
            .setOngoing(running)
            .setOnlyAlertOnce(true)
            .setPriority(if (minimal) NotificationCompat.PRIORITY_MIN else NotificationCompat.PRIORITY_LOW)

        // The quick on/off action is dropped in minimal mode to keep it terse.
        if (!minimal) {
            val toggleIntent = Intent(context, NotificationActionReceiver::class.java)
                .setAction(NotificationActionReceiver.ACTION_TOGGLE)
            val togglePendingIntent = PendingIntent.getBroadcast(
                context,
                0,
                toggleIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            val actionLabel = if (running) {
                context.getString(R.string.notification_action_turn_off)
            } else {
                context.getString(R.string.notification_action_turn_on)
            }
            builder.addAction(0, actionLabel, togglePendingIntent)
        }

        return builder.build()
    }

    fun updateNotification(context: Context, running: Boolean, blockedCount: Long) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildStatusNotification(context, running, blockedCount))
    }

    fun dismiss(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.cancel(NOTIFICATION_ID)
    }
}
