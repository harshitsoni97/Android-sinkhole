package com.sinkhole.adblock

import android.app.Application
import com.sinkhole.adblock.log.SinkholeLog
import com.sinkhole.adblock.notification.NotificationHelper

class SinkholeApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        SinkholeLog.init(this)
        NotificationHelper.ensureChannel(this)
    }
}
