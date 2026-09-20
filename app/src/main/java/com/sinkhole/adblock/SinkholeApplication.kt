package com.sinkhole.adblock

import android.app.Application
import com.sinkhole.adblock.notification.NotificationHelper

class SinkholeApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        NotificationHelper.ensureChannel(this)
    }
}
