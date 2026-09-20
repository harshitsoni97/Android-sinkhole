package com.sinkhole.adblock.log

import android.content.Context
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.ConcurrentLinkedDeque

/**
 * The app's own log buffer, separate from system logcat.
 *
 * Third-party apps can't reliably read the system log on modern Android
 * (READ_LOGS is signature/system-only since API 23), so if we want a
 * "view/copy logs in the app" feature that actually works, we have to keep
 * our own record of what we log. Every call also still goes through
 * [android.util.Log] as normal, so `adb logcat` keeps working too.
 *
 * Kept as an in-memory ring buffer (fast, always available) backed by a
 * capped file (survives the app process dying/restarting, which is exactly
 * when these logs are most useful).
 */
object SinkholeLog {

    private const val MAX_LINES = 1500
    private const val MAX_FILE_BYTES = 512 * 1024
    private const val LOG_FILE_NAME = "sinkhole_log.txt"

    private val buffer = ConcurrentLinkedDeque<String>()
    private val timeFormat = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)

    @Volatile private var logFile: File? = null

    fun init(context: Context) {
        if (logFile != null) return
        val file = File(context.applicationContext.filesDir, LOG_FILE_NAME)
        logFile = file
        if (file.exists()) {
            try {
                file.readLines().takeLast(MAX_LINES).forEach { buffer.addLast(it) }
            } catch (_: Exception) {
            }
        }
    }

    fun d(tag: String, message: String) {
        Log.d(tag, message)
        append("D", tag, message)
    }

    fun i(tag: String, message: String) {
        Log.i(tag, message)
        append("I", tag, message)
    }

    fun w(tag: String, message: String, throwable: Throwable? = null) {
        if (throwable != null) Log.w(tag, message, throwable) else Log.w(tag, message)
        append("W", tag, message, throwable)
    }

    fun e(tag: String, message: String, throwable: Throwable? = null) {
        if (throwable != null) Log.e(tag, message, throwable) else Log.e(tag, message)
        append("E", tag, message, throwable)
    }

    fun getLogText(): String = buffer.joinToString("\n")

    fun clear() {
        buffer.clear()
        try {
            logFile?.writeText("")
        } catch (_: Exception) {
        }
    }

    private fun append(level: String, tag: String, message: String, throwable: Throwable? = null) {
        val suffix = throwable?.let { " — ${it}" } ?: ""
        val line = "${timeFormat.format(System.currentTimeMillis())} $level/$tag: $message$suffix"

        buffer.addLast(line)
        while (buffer.size > MAX_LINES) buffer.pollFirst()

        val file = logFile ?: return
        try {
            file.appendText(line + "\n")
            if (file.length() > MAX_FILE_BYTES) {
                file.writeText(buffer.joinToString("\n") + "\n")
            }
        } catch (_: Exception) {
        }
    }
}
