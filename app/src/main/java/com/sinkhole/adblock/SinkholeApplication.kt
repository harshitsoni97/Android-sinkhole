package com.sinkhole.adblock

import android.app.Application
import com.google.android.material.color.DynamicColors
import com.sinkhole.adblock.log.SinkholeLog
import com.sinkhole.adblock.notification.NotificationHelper

class SinkholeApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Material You: recolor the app from the user's wallpaper on Android
        // 12+. No-op on older versions, which fall back to the static theme.
        DynamicColors.applyToActivitiesIfAvailable(this)
        SinkholeLog.init(this)
        NotificationHelper.ensureChannel(this)
    }
}
