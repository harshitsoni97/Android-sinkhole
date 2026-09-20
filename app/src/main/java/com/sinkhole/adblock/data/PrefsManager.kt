package com.sinkhole.adblock.data

import android.content.Context
import android.content.SharedPreferences

/** Small wrapper around the app's single SharedPreferences file. */
class PrefsManager(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    var protectionEnabled: Boolean
        get() = prefs.getBoolean(KEY_ENABLED, false)
        set(value) = prefs.edit().putBoolean(KEY_ENABLED, value).apply()

    var blocklistUrl: String
        get() = prefs.getString(KEY_BLOCKLIST_URL, DEFAULT_BLOCKLIST_URL) ?: DEFAULT_BLOCKLIST_URL
        set(value) = prefs.edit().putString(KEY_BLOCKLIST_URL, value).apply()

    var blockedQueryCount: Long
        get() = prefs.getLong(KEY_BLOCKED_COUNT, 0L)
        set(value) = prefs.edit().putLong(KEY_BLOCKED_COUNT, value).apply()

    var totalQueryCount: Long
        get() = prefs.getLong(KEY_TOTAL_COUNT, 0L)
        set(value) = prefs.edit().putLong(KEY_TOTAL_COUNT, value).apply()

    var customBlockedDomains: Set<String>
        get() = prefs.getStringSet(KEY_CUSTOM_BLOCKED, emptySet()) ?: emptySet()
        set(value) = prefs.edit().putStringSet(KEY_CUSTOM_BLOCKED, value).apply()

    var whitelistedDomains: Set<String>
        get() = prefs.getStringSet(KEY_WHITELIST, emptySet()) ?: emptySet()
        set(value) = prefs.edit().putStringSet(KEY_WHITELIST, value).apply()

    var lastBlocklistUpdateMillis: Long
        get() = prefs.getLong(KEY_LAST_UPDATE, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_UPDATE, value).apply()

    fun incrementCounters(blocked: Boolean) {
        totalQueryCount += 1
        if (blocked) blockedQueryCount += 1
    }

    companion object {
        private const val PREFS_NAME = "sinkhole_prefs"
        private const val KEY_ENABLED = "protection_enabled"
        private const val KEY_BLOCKLIST_URL = "blocklist_url"
        private const val KEY_BLOCKED_COUNT = "blocked_count"
        private const val KEY_TOTAL_COUNT = "total_count"
        private const val KEY_CUSTOM_BLOCKED = "custom_blocked_domains"
        private const val KEY_WHITELIST = "whitelisted_domains"
        private const val KEY_LAST_UPDATE = "last_blocklist_update"

        const val DEFAULT_BLOCKLIST_URL =
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    }
}
