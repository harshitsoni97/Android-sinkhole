package com.sinkhole.adblock.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.sinkhole.adblock.R
import com.sinkhole.adblock.blocklist.BlocklistManager
import com.sinkhole.adblock.data.PrefsManager
import com.sinkhole.adblock.dns.DnsMessage
import com.sinkhole.adblock.net.IpPacketUtils
import com.sinkhole.adblock.notification.NotificationHelper
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
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
    private val lastNotificationUpdateMillis = AtomicLong(0)

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
            Log.e(TAG, "Failed to establish VPN interface")
            stopSelf()
            return
        }
        vpnInterface = iface
        isRunning.set(true)
        prefs.protectionEnabled = true

        startForeground(
            NotificationHelper.NOTIFICATION_ID,
            NotificationHelper.buildStatusNotification(this, true, blockedCounter.get()),
        )

        val pool = Executors.newFixedThreadPool(WORKER_THREADS)
        workerPool = pool
        tunnelThread = Thread({ runTunnelLoop(iface, pool) }, "sinkhole-tunnel").also { it.start() }
    }

    private fun stopVpn() {
        if (!isRunning.getAndSet(false)) {
            stopSelf()
            return
        }

        persistCounters()
        prefs.protectionEnabled = false

        tunnelThread?.interrupt()
        tunnelThread = null

        workerPool?.shutdownNow()
        workerPool = null

        try {
            vpnInterface?.close()
        } catch (e: IOException) {
            Log.w(TAG, "Error closing VPN interface: ${e.message}")
        }
        vpnInterface = null

        stopForeground(STOP_FOREGROUND_DETACH)
        NotificationHelper.updateNotification(this, false, blockedCounter.get())
        stopSelf()
    }

    private fun establishInterface(): ParcelFileDescriptor? {
        return try {
            Builder()
                .setSession(getString(R.string.app_name))
                .addAddress(VPN_ADDRESS, 32)
                .addDnsServer(VPN_ADDRESS)
                .addRoute(VPN_ADDRESS, 32)
                .setMtu(MTU)
                .setBlocking(true)
                .establish()
        } catch (e: Exception) {
            Log.e(TAG, "establish() failed: ${e.message}")
            null
        }
    }

    private fun runTunnelLoop(iface: ParcelFileDescriptor, pool: ExecutorService) {
        val input = FileInputStream(iface.fileDescriptor)
        val output = FileOutputStream(iface.fileDescriptor)
        val buffer = ByteArray(MAX_PACKET_SIZE)

        try {
            while (isRunning.get() && !Thread.currentThread().isInterrupted) {
                val length = try {
                    input.read(buffer)
                } catch (e: IOException) {
                    if (isRunning.get()) Log.w(TAG, "tun read failed: ${e.message}")
                    break
                }
                if (length <= 0) continue
                if (!isDnsPacket(buffer, length)) continue

                val packet = buffer.copyOf(length)
                try {
                    pool.execute { handleDnsPacket(packet, output) }
                } catch (e: java.util.concurrent.RejectedExecutionException) {
                    // Pool is shutting down; drop the packet.
                }
            }
        } finally {
            try {
                input.close()
            } catch (_: IOException) {
            }
        }
    }

    private fun isDnsPacket(packet: ByteArray, length: Int): Boolean {
        if (length < IpPacketUtils.IPV4_HEADER_LENGTH) return false
        if (IpPacketUtils.ipVersion(packet) != 4) return false
        val ipHeaderLen = IpPacketUtils.ipHeaderLength(packet)
        if (ipHeaderLen < IpPacketUtils.IPV4_HEADER_LENGTH || ipHeaderLen + IpPacketUtils.UDP_HEADER_LENGTH > length) {
            return false
        }
        if (IpPacketUtils.protocol(packet) != IpPacketUtils.PROTOCOL_UDP) return false
        return IpPacketUtils.udpDestPort(packet, ipHeaderLen) == DNS_PORT
    }

    private fun handleDnsPacket(packet: ByteArray, output: FileOutputStream) {
        try {
            val ipHeaderLen = IpPacketUtils.ipHeaderLength(packet)
            val srcIp = IpPacketUtils.sourceAddress(packet)
            val dstIp = IpPacketUtils.destAddress(packet)
            val srcPort = IpPacketUtils.udpSourcePort(packet, ipHeaderLen)
            val dnsQuery = IpPacketUtils.udpPayload(packet, packet.size, ipHeaderLen)

            val parsed = DnsMessage.parseQuery(dnsQuery, dnsQuery.size)
            val blocked = parsed != null && blocklistManager.isBlocked(parsed.queryName)

            totalCounter.incrementAndGet()
            if (blocked) blockedCounter.incrementAndGet()
            maybeRefreshNotification()

            val responsePayload = if (blocked && parsed != null) {
                DnsMessage.buildBlockedResponse(dnsQuery, parsed)
            } else {
                forwardToUpstream(dnsQuery)
            } ?: return

            val replyPacket = IpPacketUtils.buildIpv4UdpPacket(
                srcIp = dstIp,
                srcPort = DNS_PORT,
                dstIp = srcIp,
                dstPort = srcPort,
                payload = responsePayload,
            )

            synchronized(outputLock) {
                output.write(replyPacket)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed handling DNS packet: ${e.message}")
        }
    }

    private fun forwardToUpstream(query: ByteArray): ByteArray? {
        for (server in UPSTREAM_SERVERS) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                protect(socket)
                socket.soTimeout = UPSTREAM_TIMEOUT_MS
                val address = InetAddress.getByName(server)
                socket.send(DatagramPacket(query, query.size, address, DNS_PORT))

                val responseBuffer = ByteArray(MAX_PACKET_SIZE)
                val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                socket.receive(responsePacket)
                return responseBuffer.copyOf(responsePacket.length)
            } catch (e: IOException) {
                continue
            } finally {
                socket?.close()
            }
        }
        return null
    }

    private fun maybeRefreshNotification() {
        val now = System.currentTimeMillis()
        val prev = lastNotificationUpdateMillis.get()
        if (now - prev >= NOTIFICATION_THROTTLE_MS && lastNotificationUpdateMillis.compareAndSet(prev, now)) {
            NotificationHelper.updateNotification(this, true, blockedCounter.get())
            persistCounters()
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

        private const val VPN_ADDRESS = "10.111.222.1"
        private const val DNS_PORT = 53
        private const val MTU = 1500
        private const val MAX_PACKET_SIZE = 32767
        private const val WORKER_THREADS = 4
        private const val UPSTREAM_TIMEOUT_MS = 4000
        private const val NOTIFICATION_THROTTLE_MS = 1000L

        private val UPSTREAM_SERVERS = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9")

        /** Reflects whether the tunnel is currently established. */
        val isRunning = AtomicBoolean(false)
    }
}
