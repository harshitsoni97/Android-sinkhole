package com.sinkhole.adblock.dns

/**
 * A small, TTL-aware, in-memory cache of upstream DNS answers, keyed by
 * (query name, query type). Serving a repeat lookup from here avoids a
 * network round-trip, which cuts latency and radio wakeups (battery).
 *
 * Deliberately kept tiny and RAM-only (nothing is written to disk, so it
 * costs no device storage): a bounded LRU of at most [maxEntries] entries,
 * skipping oversized responses, with TTLs clamped so nothing is cached for
 * too long or churned for trivially short TTLs.
 */
class DnsCache(
    private val maxEntries: Int = 512,
    private val minTtlSeconds: Long = 5,
    private val maxTtlSeconds: Long = 3600,
    private val maxResponseBytes: Int = 1500,
) {

    private class Entry(val response: ByteArray, val expiresAtMillis: Long)

    // access-order LRU: eldest (least recently used) is evicted past capacity.
    private val map = object : LinkedHashMap<String, Entry>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Entry>): Boolean =
            size > maxEntries
    }

    fun key(name: String, type: Int): String = "${name.lowercase()}|$type"

    /** Returns a cached response for [key] if present and unexpired, else null. */
    @Synchronized
    fun get(key: String): ByteArray? {
        val entry = map[key] ?: return null
        if (System.currentTimeMillis() >= entry.expiresAtMillis) {
            map.remove(key)
            return null
        }
        return entry.response
    }

    /** Caches [response] for [ttlSeconds] (clamped). No-op for oversized payloads. */
    @Synchronized
    fun put(key: String, response: ByteArray, ttlSeconds: Long) {
        if (response.size > maxResponseBytes) return
        val ttl = ttlSeconds.coerceIn(minTtlSeconds, maxTtlSeconds)
        map[key] = Entry(response.copyOf(), System.currentTimeMillis() + ttl * 1000L)
    }

    @Synchronized
    fun clear() = map.clear()
}
