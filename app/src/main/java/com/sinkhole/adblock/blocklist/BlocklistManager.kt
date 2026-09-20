package com.sinkhole.adblock.blocklist

import android.content.Context
import com.sinkhole.adblock.data.PrefsManager
import com.sinkhole.adblock.log.SinkholeLog
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.Collections
import java.util.concurrent.atomic.AtomicReference

/**
 * Holds the set of domains to sinkhole. Seeded from a bundled asset on first
 * run, and can be refreshed from a remote hosts-file style URL. Also honours
 * a small user-managed whitelist/blacklist stored in [PrefsManager].
 *
 * Thread-safe: [isBlocked] may be called concurrently from multiple worker
 * threads handling in-flight DNS queries while [loadInitial]/[updateFromUrl]
 * swap in a new snapshot from a background thread.
 */
class BlocklistManager(private val context: Context, private val prefs: PrefsManager) {

    private val domainsRef = AtomicReference<Set<String>>(emptySet())

    private val cacheFile: File
        get() = File(context.filesDir, "blocklist_downloaded.txt")

    /** Loads the on-disk cached list if present, otherwise the bundled asset. */
    fun loadInitial() {
        val fromCache = if (cacheFile.exists()) parseHostsStream(cacheFile.inputStream()) else null
        val base = fromCache ?: parseHostsStream(context.assets.open(ASSET_NAME))
        domainsRef.set(base)
        SinkholeLog.i(TAG, "Loaded ${base.size} blocklist entries (${if (fromCache != null) "cache" else "bundled asset"})")
    }

    /** Re-reads the bundled asset, discarding any downloaded list. */
    fun resetToBundled() {
        cacheFile.delete()
        domainsRef.set(parseHostsStream(context.assets.open(ASSET_NAME)))
    }

    /**
     * Downloads a fresh hosts-file style list from [urlString] and, on
     * success, persists it as the new cache and swaps it in. Runs network IO
     * on the calling thread — callers should invoke this off the main thread.
     * Returns the number of parsed domains, or null on failure.
     */
    fun updateFromUrl(urlString: String): Int? {
        return try {
            val connection = (URL(urlString).openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000
                readTimeout = 20_000
                requestMethod = "GET"
            }
            connection.inputStream.use { input ->
                val bytes = input.readBytes()
                cacheFile.writeBytes(bytes)
            }
            connection.disconnect()
            val parsed = parseHostsStream(cacheFile.inputStream())
            domainsRef.set(parsed)
            prefs.lastBlocklistUpdateMillis = System.currentTimeMillis()
            parsed.size
        } catch (e: Exception) {
            SinkholeLog.w(TAG, "Blocklist update from $urlString failed: ${e.message}")
            null
        }
    }

    /** True if [domain] (or any parent domain of it) should be sinkholed. */
    fun isBlocked(domain: String): Boolean {
        val name = domain.trimEnd('.').lowercase()
        if (name.isEmpty()) return false

        val whitelist = prefs.whitelistedDomains
        if (matchesAnySuffix(name, whitelist)) return false

        val custom = prefs.customBlockedDomains
        if (matchesAnySuffix(name, custom)) return true

        return matchesAnySuffix(name, domainsRef.get())
    }

    fun blockedDomainCount(): Int = domainsRef.get().size

    /** Checks [name] and each of its parent domains against [set]. */
    private fun matchesAnySuffix(name: String, set: Set<String>): Boolean {
        if (set.isEmpty()) return false
        var current = name
        while (true) {
            if (set.contains(current)) return true
            val dot = current.indexOf('.')
            if (dot < 0) return false
            current = current.substring(dot + 1)
        }
    }

    /**
     * Parses either a plain domain-per-line list or a hosts-file
     * (`0.0.0.0 domain.tld` / `127.0.0.1 domain.tld`) formatted stream.
     */
    private fun parseHostsStream(stream: java.io.InputStream): Set<String> {
        val result = mutableSetOf<String>()
        BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { reader ->
            reader.forEachLine { rawLine ->
                val line = rawLine.substringBefore('#').trim()
                if (line.isEmpty()) return@forEachLine

                val tokens = line.split(Regex("\\s+"))
                val domain = when {
                    tokens.size >= 2 && (tokens[0] == "0.0.0.0" || tokens[0] == "127.0.0.1") -> tokens[1]
                    tokens.size == 1 -> tokens[0]
                    else -> null
                }
                val normalized = domain?.trim()?.trimEnd('.')?.lowercase()
                if (!normalized.isNullOrEmpty() &&
                    normalized != "localhost" &&
                    normalized != "localhost.localdomain" &&
                    normalized != "local" &&
                    normalized != "broadcasthost" &&
                    normalized.contains('.')
                ) {
                    result.add(normalized)
                }
            }
        }
        return Collections.unmodifiableSet(result)
    }

    companion object {
        private const val TAG = "BlocklistManager"
        private const val ASSET_NAME = "blocklist.txt"
    }
}
