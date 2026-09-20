package com.sinkhole.adblock.net

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal, allocation-light helpers for reading/writing raw IPv4 + UDP headers
 * on packets read from / written to the VpnService TUN file descriptor.
 *
 * We only ever see IPv4/UDP/port-53 traffic here (the VPN is configured to
 * route just the fake DNS server address through the tunnel), so this does
 * not attempt to be a general-purpose IP stack.
 */
object IpPacketUtils {

    const val IPV4_HEADER_LENGTH = 20
    const val UDP_HEADER_LENGTH = 8
    const val PROTOCOL_UDP = 17

    fun ipVersion(packet: ByteArray): Int = (packet[0].toInt() shr 4) and 0x0F

    fun ipHeaderLength(packet: ByteArray): Int = (packet[0].toInt() and 0x0F) * 4

    fun protocol(packet: ByteArray): Int = packet[9].toInt() and 0xFF

    fun sourceAddress(packet: ByteArray): ByteArray = packet.copyOfRange(12, 16)
    fun destAddress(packet: ByteArray): ByteArray = packet.copyOfRange(16, 20)

    fun udpSourcePort(packet: ByteArray, ipHeaderLen: Int): Int {
        val off = ipHeaderLen
        return ((packet[off].toInt() and 0xFF) shl 8) or (packet[off + 1].toInt() and 0xFF)
    }

    fun udpDestPort(packet: ByteArray, ipHeaderLen: Int): Int {
        val off = ipHeaderLen + 2
        return ((packet[off].toInt() and 0xFF) shl 8) or (packet[off + 1].toInt() and 0xFF)
    }

    /** Returns the UDP payload (i.e. the raw DNS message) from a captured packet. */
    fun udpPayload(packet: ByteArray, length: Int, ipHeaderLen: Int): ByteArray {
        val payloadStart = ipHeaderLen + UDP_HEADER_LENGTH
        return packet.copyOfRange(payloadStart, length)
    }

    /**
     * Sums 16-bit big-endian words of `data[offset, offset+length)` using
     * one's complement addition (RFC 1071), folding carries as it goes.
     * `initial` seeds the sum so pseudo-header + segment sums can be combined.
     */
    private fun onesComplementSum(data: ByteArray, offset: Int, length: Int, initial: Long = 0L): Long {
        var sum = initial
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum
    }

    private fun checksumFromSum(sum: Long): Int = (sum.inv() and 0xFFFF).toInt()

    fun ipv4HeaderChecksum(header: ByteArray): Int =
        checksumFromSum(onesComplementSum(header, 0, IPV4_HEADER_LENGTH))

    /**
     * Builds a full IPv4+UDP reply packet: [srcIp:srcPort] -> [dstIp:dstPort]
     * carrying [payload]. Both the IPv4 header checksum and UDP checksum are
     * computed correctly so the packet is accepted by strict validators.
     */
    fun buildIpv4UdpPacket(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        payload: ByteArray,
        identification: Int = 0,
    ): ByteArray {
        val udpLength = UDP_HEADER_LENGTH + payload.size
        val totalLength = IPV4_HEADER_LENGTH + udpLength
        val buffer = ByteBuffer.allocate(totalLength).order(ByteOrder.BIG_ENDIAN)

        // --- IPv4 header ---
        buffer.put((0x45).toByte()) // version 4, IHL 5 (20 bytes, no options)
        buffer.put(0.toByte()) // DSCP/ECN
        buffer.putShort(totalLength.toShort())
        buffer.putShort(identification.toShort())
        buffer.putShort(0x4000.toShort()) // flags: don't fragment
        buffer.put(64.toByte()) // TTL
        buffer.put(PROTOCOL_UDP.toByte())
        buffer.putShort(0.toShort()) // checksum placeholder
        buffer.put(srcIp)
        buffer.put(dstIp)

        // --- UDP header ---
        buffer.putShort(srcPort.toShort())
        buffer.putShort(dstPort.toShort())
        buffer.putShort(udpLength.toShort())
        buffer.putShort(0.toShort()) // UDP checksum placeholder
        buffer.put(payload)

        val bytes = buffer.array()

        // Fill in the IPv4 header checksum.
        val ipChecksum = ipv4HeaderChecksum(bytes.copyOfRange(0, IPV4_HEADER_LENGTH))
        bytes[10] = ((ipChecksum shr 8) and 0xFF).toByte()
        bytes[11] = (ipChecksum and 0xFF).toByte()

        // Fill in the UDP checksum (pseudo-header + UDP segment).
        val udpChecksum = udpChecksum(srcIp, dstIp, bytes, IPV4_HEADER_LENGTH, udpLength)
        val udpChecksumOffset = IPV4_HEADER_LENGTH + 6
        bytes[udpChecksumOffset] = ((udpChecksum shr 8) and 0xFF).toByte()
        bytes[udpChecksumOffset + 1] = (udpChecksum and 0xFF).toByte()

        return bytes
    }

    private fun udpChecksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        packet: ByteArray,
        udpOffset: Int,
        udpLength: Int,
    ): Int {
        val pseudoHeader = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        pseudoHeader.put(srcIp)
        pseudoHeader.put(dstIp)
        pseudoHeader.put(0.toByte())
        pseudoHeader.put(PROTOCOL_UDP.toByte())
        pseudoHeader.putShort(udpLength.toShort())

        val pseudoSum = onesComplementSum(pseudoHeader.array(), 0, 12)
        val totalSum = onesComplementSum(packet, udpOffset, udpLength, pseudoSum)
        val checksum = checksumFromSum(totalSum)
        // RFC 768: a computed checksum of 0 is transmitted as all-ones.
        return if (checksum == 0) 0xFFFF else checksum
    }
}
