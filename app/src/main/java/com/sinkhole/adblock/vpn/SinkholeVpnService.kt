package com.sinkhole.adblock.vpn

import android.content.ComponentName
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import com.sinkhole.adblock.R
import com.sinkhole.adblock.blocklist.BlocklistManager
import com.sinkhole.adblock.data.PrefsManager
import com.sinkhole.adblock.dns.DnsMessage
import com.sinkhole.adblock.log.SinkholeLog
import com.sinkhole.adblock.net.IpPacketUtils
import com.sinkhole.adblock.notification.NotificationHelper
import com.sinkhole.adblock.tile.SinkholeTileService
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * A local, DNS-only VPN: only traffic destined for our fake DNS server
 * address is routed through the TUN interface (see [establishInterface]), so
 * every other connection an app makes continues straight over the real
 * network. DNS queries that arrive on the tunnel are answered locally
 * ("sinkholed") when the requested domain is on the blocklist, otherwise
 * forwarded verbatim to a real upstream resolver and the answer relayed back.
 */
class SinkholeVpnService : VpnService() {

    private lateinit var prefs: PrefsManager
    private lateinit var blocklistManager: BlocklistManager

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnelThread: Thread? = null
    private var workerPool: ExecutorService? = null
    private val outputLock = Object()

    private val blockedCounter = AtomicLong(0)
    private val totalCounter = AtomicLong(0)
    private val lastStateUpdateMillis = AtomicLong(0)
    @Volatile private var lastNotifiedBlocked = 0L
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onCreate() {
        super.onCreate()
        prefs = PrefsManager(this)
        blocklistManager = BlocklistManager(this, prefs)
        blocklistManager.loadInitial()
        blockedCounter.set(prefs.blockedQueryCount)
        totalCounter.set(prefs.totalQueryCount)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            ACTION_REFRESH_NOTIFICATION -> {
                if (isRunning.get()) {
                    startForeground(
                        NotificationHelper.NOTIFICATION_ID,
                        NotificationHelper.buildStatusNotification(this, true, blockedCounter.get()),
                    )
                }
                return START_STICKY
            }
            else -> {
                startVpn()
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun startVpn() {
        if (isRunning.get()) return

        val iface = establishInterface()
        if (iface == null) {
            SinkholeLog.e(TAG, "Failed to establish VPN interface")
            stopSelf()
            return
        }
        SinkholeLog.i(TAG, "VPN interface established: dns=$DNS_ADDRESS,$DNS_ADDRESS_V6 mtu=$MTU")
        vpnInterface = iface
        isRunning.set(true)
        prefs.protectionEnabled = true

        startForeground(
            NotificationHelper.NOTIFICATION_ID,
            NotificationHelper.buildStatusNotification(this, true, blockedCounter.get()),
        )

        lastNotifiedBlocked = blockedCounter.get()
        // Bounded, self-shrinking pool: worker threads exit after a short
        // idle period (no lingering threads while the phone sits idle), and
        // the capped queue drops excess under a DNS flood (clients just
        // retry) rather than letting a backlog balloon memory.
        val pool = ThreadPoolExecutor(
            WORKER_THREADS,
            WORKER_THREADS,
            THREAD_KEEPALIVE_SECONDS,
            TimeUnit.SECONDS,
            LinkedBlockingQueue(MAX_QUEUED_QUERIES),
            ThreadPoolExecutor.DiscardPolicy(),
        ).apply { allowCoreThreadTimeOut(true) }
        workerPool = pool
        tunnelThread = Thread({ runTunnelLoop(iface, pool) }, "sinkhole-tunnel").also { it.start() }
        requestTileRefresh()
    }

    private fun stopVpn() {
        if (!isRunning.getAndSet(false)) {
            stopSelf()
            return
        }

        persistCounters()
        SinkholeLog.flush()
        prefs.protectionEnabled = false

        tunnelThread?.interrupt()
        tunnelThread = null

        workerPool?.shutdownNow()
        workerPool = null

        try {
            vpnInterface?.close()
        } catch (e: IOException) {
            SinkholeLog.w(TAG, "Error closing VPN interface: ${e.message}")
        }
        vpnInterface = null

        stopForeground(STOP_FOREGROUND_DETACH)
        NotificationHelper.updateNotification(this, false, blockedCounter.get())
        requestTileRefresh()
        stopSelf()
    }

    private fun requestTileRefresh() {
        try {
            TileService.requestListeningState(this, ComponentName(this, SinkholeTileService::class.java))
        } catch (e: Exception) {
            SinkholeLog.w(TAG, "Could not refresh QS tile: ${e.message}")
        }
    }

    private fun establishInterface(): ParcelFileDescriptor? {
        return try {
            // CRITICAL: the DNS server address must be DIFFERENT from the
            // interface address. A packet destined to an address assigned to
            // the tun interface itself is treated as local by the kernel and
            // delivered via loopback — it never egresses the tun for us to
            // read(). So the interface takes .1 and the (routed but
            // unassigned) DNS server address is .2; queries the OS sends to
            // the DNS server are then forwarded out the tun and we see them.
            val builder = Builder()
                .setSession(getString(R.string.app_name))
                .addAddress(VPN_ADDRESS, 32)
                .addDnsServer(DNS_ADDRESS)
                .addRoute(DNS_ADDRESS, 32)
                .setMtu(MTU)
                .setBlocking(true)

            // Best-effort: many networks are dual-stack and hand out DNS
            // over IPv6, which an IPv4-only fake resolver would never see.
            // If IPv6 setup fails for some reason, fall back to IPv4-only
            // rather than losing the VPN entirely.
            try {
                builder.addAddress(VPN_ADDRESS_V6, 128)
                builder.addDnsServer(DNS_ADDRESS_V6)
                builder.addRoute(DNS_ADDRESS_V6, 128)
            } catch (e: Exception) {
                SinkholeLog.w(TAG, "IPv6 tunnel setup failed, continuing IPv4-only: ${e.message}")
            }

            builder.establish()
        } catch (e: Exception) {
            SinkholeLog.e(TAG, "establish() failed: ${e.message}")
            null
        }
    }

    private fun runTunnelLoop(iface: ParcelFileDescriptor, pool: ExecutorService) {
        val input = FileInputStream(iface.fileDescriptor)
        val output = FileOutputStream(iface.fileDescriptor)
        val buffer = ByteArray(MAX_PACKET_SIZE)
        var packetsSeen = 0L
        var dnsPacketsSeen = 0L
        var lastStatsLogMillis = 0L

        SinkholeLog.i(TAG, "Tunnel loop starting; waiting for DNS on $DNS_ADDRESS / $DNS_ADDRESS_V6")

        try {
            while (isRunning.get() && !Thread.currentThread().isInterrupted) {
                val length = try {
                    input.read(buffer)
                } catch (e: IOException) {
                    if (isRunning.get()) SinkholeLog.w(TAG, "tun read failed: ${e.message}")
                    break
                }
                if (length < 0) break // tun fd closed / EOF — stop, don't busy-loop
                if (length == 0) continue

                packetsSeen++
                val dnsIpHeaderLen = dnsIpHeaderLength(buffer, length)
                val isDns = dnsIpHeaderLen >= 0
                if (isDns) dnsPacketsSeen++

                // Heartbeat so we can tell, from logs alone, whether ANY
                // traffic is reaching the tunnel at all (vs. it arriving but
                // not being recognized as DNS, vs. nothing arriving).
                val now = System.currentTimeMillis()
                if (now - lastStatsLogMillis >= TUNNEL_STATS_LOG_INTERVAL_MS) {
                    lastStatsLogMillis = now
                    val version = IpPacketUtils.ipVersion(buffer)
                    val protocol = when {
                        version == 6 && length >= IpPacketUtils.IPV6_HEADER_LENGTH ->
                            IpPacketUtils.ipv6NextHeader(buffer)
                        version == 4 && length >= IpPacketUtils.IPV4_HEADER_LENGTH ->
                            IpPacketUtils.protocol(buffer)
                        else -> -1
                    }
                    SinkholeLog.d(
                        TAG,
                        "tunnel traffic: seen=$packetsSeen dns=$dnsPacketsSeen " +
                            "lastPacket(ipVersion=$version protocol=$protocol length=$length)",
                    )
                }

                if (!isDns) continue

                val packet = buffer.copyOf(length)
                try {
                    pool.execute { handleDnsPacket(packet, output) }
                } catch (e: java.util.concurrent.RejectedExecutionException) {
                    // Pool is shutting down; drop the packet.
                }
            }
        } catch (t: Throwable) {
            // Anything escaping here would otherwise kill this background
            // thread (and, on Android, the whole process) silently, leaving
            // the OS pointed at a DNS server nobody is servicing anymore —
            // i.e. total DNS failure until the user manually disables the
            // VPN. Tear protection down cleanly instead so the system falls
            // back to normal DNS.
            SinkholeLog.e(TAG, "Tunnel loop crashed unexpectedly, disabling protection: ${t.message}", t)
            mainHandler.post { stopVpn() }
        } finally {
            try {
                input.close()
            } catch (_: IOException) {
            }
        }
    }

    /**
     * Returns the IP header length if [packet] is an IPv4 or IPv6 UDP/53
     * query we should handle, or -1 otherwise.
     */
    private fun dnsIpHeaderLength(packet: ByteArray, length: Int): Int {
        return when (IpPacketUtils.ipVersion(packet)) {
            4 -> {
                if (length < IpPacketUtils.IPV4_HEADER_LENGTH) return -1
                val ipHeaderLen = IpPacketUtils.ipHeaderLength(packet)
                if (ipHeaderLen < IpPacketUtils.IPV4_HEADER_LENGTH ||
                    ipHeaderLen + IpPacketUtils.UDP_HEADER_LENGTH > length
                ) {
                    return -1
                }
                if (IpPacketUtils.protocol(packet) != IpPacketUtils.PROTOCOL_UDP) return -1
                if (IpPacketUtils.udpDestPort(packet, ipHeaderLen) != DNS_PORT) return -1
                ipHeaderLen
            }
            6 -> {
                if (length < IpPacketUtils.IPV6_HEADER_LENGTH + IpPacketUtils.UDP_HEADER_LENGTH) return -1
                if (IpPacketUtils.ipv6NextHeader(packet) != IpPacketUtils.PROTOCOL_UDP) return -1
                if (IpPacketUtils.udpDestPort(packet, IpPacketUtils.IPV6_HEADER_LENGTH) != DNS_PORT) return -1
                IpPacketUtils.IPV6_HEADER_LENGTH
            }
            else -> -1
        }
    }

    private fun handleDnsPacket(packet: ByteArray, output: FileOutputStream) {
        try {
            val version = IpPacketUtils.ipVersion(packet)
            val ipHeaderLen = if (version == 4) {
                IpPacketUtils.ipHeaderLength(packet)
            } else {
                IpPacketUtils.IPV6_HEADER_LENGTH
            }
            val srcIp = if (version == 4) IpPacketUtils.sourceAddress(packet) else IpPacketUtils.ipv6SourceAddress(packet)
            val dstIp = if (version == 4) IpPacketUtils.destAddress(packet) else IpPacketUtils.ipv6DestAddress(packet)
            val srcPort = IpPacketUtils.udpSourcePort(packet, ipHeaderLen)
            val dnsQuery = IpPacketUtils.udpPayload(packet, packet.size, ipHeaderLen)

            val parsed = DnsMessage.parseQuery(dnsQuery, dnsQuery.size)
            val blocked = parsed != null && blocklistManager.isBlocked(parsed.queryName)

            totalCounter.incrementAndGet()
            if (blocked) blockedCounter.incrementAndGet()
            maybeRefreshState()

            val responsePayload = if (blocked && parsed != null) {
                DnsMessage.buildBlockedResponse(dnsQuery, parsed)
            } else {
                forwardToUpstream(dnsQuery)
            }
            if (responsePayload == null) {
                SinkholeLog.w(TAG, "No upstream response for ${parsed?.queryName ?: "unparsed query"}; all resolvers failed")
                return
            }

            val replyPacket = if (version == 4) {
                IpPacketUtils.buildIpv4UdpPacket(
                    srcIp = dstIp,
                    srcPort = DNS_PORT,
                    dstIp = srcIp,
                    dstPort = srcPort,
                    payload = responsePayload,
                )
            } else {
                IpPacketUtils.buildIpv6UdpPacket(
                    srcIp = dstIp,
                    srcPort = DNS_PORT,
                    dstIp = srcIp,
                    dstPort = srcPort,
                    payload = responsePayload,
                )
            }

            synchronized(outputLock) {
                output.write(replyPacket)
            }
            SinkholeLog.d(
                TAG,
                "DNS ${if (blocked) "blocked" else "resolved"} (v$version): ${parsed?.queryName ?: "?"} " +
                    "(type=${parsed?.queryType}, replyBytes=${responsePayload.size})",
            )
        } catch (e: Exception) {
            SinkholeLog.w(TAG, "Failed handling DNS packet: ${e.message}")
        }
    }

    private fun forwardToUpstream(query: ByteArray): ByteArray? {
        for (server in UPSTREAM_SERVERS) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                if (!protect(socket)) {
                    SinkholeLog.w(TAG, "protect() failed for upstream socket to $server")
                }
                socket.soTimeout = UPSTREAM_TIMEOUT_MS
                val address = InetAddress.getByName(server)
                socket.send(DatagramPacket(query, query.size, address, DNS_PORT))

                val responseBuffer = ByteArray(UPSTREAM_RESPONSE_BUFFER)
                val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                socket.receive(responsePacket)
                return responseBuffer.copyOf(responsePacket.length)
            } catch (e: IOException) {
                SinkholeLog.w(TAG, "Forwarding to $server failed: ${e.message}")
                continue
            } finally {
                socket?.close()
            }
        }
        return null
    }

    /**
     * Throttled housekeeping run from the DNS workers: persist counters and
     * flush the log buffer at most once per [STATE_THROTTLE_MS], and repost
     * the notification only when the blocked count actually changed. This
     * keeps notification posts and disk writes off the per-query hot path so
     * heavy browsing doesn't translate into constant wakeups / IO.
     */
    private fun maybeRefreshState() {
        val now = System.currentTimeMillis()
        val prev = lastStateUpdateMillis.get()
        if (now - prev >= STATE_THROTTLE_MS && lastStateUpdateMillis.compareAndSet(prev, now)) {
            persistCounters()
            SinkholeLog.flush()
            val blocked = blockedCounter.get()
            if (blocked != lastNotifiedBlocked) {
                lastNotifiedBlocked = blocked
                NotificationHelper.updateNotification(this, true, blocked)
            }
        }
    }

    private fun persistCounters() {
        prefs.blockedQueryCount = blockedCounter.get()
        prefs.totalQueryCount = totalCounter.get()
    }

    companion object {
        private const val TAG = "SinkholeVpnService"

        const val ACTION_START = "com.sinkhole.adblock.action.START"
        const val ACTION_STOP = "com.sinkhole.adblock.action.STOP"
        const val ACTION_REFRESH_NOTIFICATION = "com.sinkhole.adblock.action.REFRESH_NOTIFICATION"

        private const val VPN_ADDRESS = "10.111.222.1"
        private const val DNS_ADDRESS = "10.111.222.2"
        private const val VPN_ADDRESS_V6 = "fdaa:1:1::1"
        private const val DNS_ADDRESS_V6 = "fdaa:1:1::2"
        private const val DNS_PORT = 53
        private const val MTU = 1500
        private const val MAX_PACKET_SIZE = 32767
        // UDP DNS responses are bounded by the client's advertised EDNS0
        // buffer (typically <= 4096); no need to allocate 32K per query.
        private const val UPSTREAM_RESPONSE_BUFFER = 4096
        private const val WORKER_THREADS = 4
        private const val THREAD_KEEPALIVE_SECONDS = 30L
        private const val MAX_QUEUED_QUERIES = 128
        private const val UPSTREAM_TIMEOUT_MS = 4000
        private const val STATE_THROTTLE_MS = 2000L
        private const val TUNNEL_STATS_LOG_INTERVAL_MS = 3000L

        private val UPSTREAM_SERVERS = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9")

        /** Reflects whether the tunnel is currently established. */
        val isRunning = AtomicBoolean(false)
    }
}
