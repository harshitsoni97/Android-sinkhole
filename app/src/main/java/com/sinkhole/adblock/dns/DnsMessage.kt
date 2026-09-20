package com.sinkhole.adblock.dns

/**
 * Lightweight parsing/building for the one message shape this app needs to
 * handle: a single-question DNS query, and a synthetic "sinkhole" reply to
 * it. This deliberately does not implement the full DNS spec (no name
 * compression on write, no multi-question support) since real-world client
 * queries we intercept always look like this.
 */
object DnsMessage {

    const val TYPE_A = 1
    const val TYPE_AAAA = 28

    private const val HEADER_LENGTH = 12

    class ParsedQuery(
        val id: Int,
        val queryName: String,
        val queryType: Int,
        val queryClass: Int,
        /** Offset immediately after the question section (qname+qtype+qclass). */
        val questionEnd: Int,
    )

    /**
     * Parses the transaction id and first question of a raw DNS message.
     * Returns null if the message is too short or malformed enough that we
     * can't safely answer it (in which case the caller should just forward
     * it upstream unmodified).
     */
    fun parseQuery(data: ByteArray, length: Int): ParsedQuery? {
        if (length < HEADER_LENGTH) return null
        val id = readUShort(data, 0)
        val qdCount = readUShort(data, 4)
        if (qdCount < 1) return null

        val nameBuilder = StringBuilder()
        var offset = HEADER_LENGTH
        var labelCount = 0
        while (offset < length) {
            val len = data[offset].toInt() and 0xFF
            if (len == 0) {
                offset += 1
                break
            }
            // Reject compression pointers / reserved bits in a query name;
            // a first question is never legitimately compressed.
            if (len and 0xC0 != 0) return null
            offset += 1
            if (offset + len > length) return null
            if (nameBuilder.isNotEmpty()) nameBuilder.append('.')
            nameBuilder.append(String(data, offset, len, Charsets.US_ASCII))
            offset += len
            labelCount += 1
            if (labelCount > 128) return null // sanity bound
        }
        if (offset + 4 > length) return null
        val qType = readUShort(data, offset)
        val qClass = readUShort(data, offset + 2)
        offset += 4

        return ParsedQuery(
            id = id,
            queryName = nameBuilder.toString(),
            queryType = qType,
            queryClass = qClass,
            questionEnd = offset,
        )
    }

    /**
     * Builds a synthetic sinkhole response for [query]: NOERROR with a
     * 0.0.0.0 / :: answer for A/AAAA questions (fast-failing the caller,
     * matching common ad-blocker DNS sinkhole behaviour), or NXDOMAIN with
     * no answers for anything else.
     */
    fun buildBlockedResponse(originalMessage: ByteArray, query: ParsedQuery): ByteArray {
        val questionSection = originalMessage.copyOfRange(HEADER_LENGTH, query.questionEnd)
        val answerable = query.queryType == TYPE_A || query.queryType == TYPE_AAAA
        val flags = if (answerable) 0x8180 else 0x8183 // QR=1,RD=1,RA=1; RCODE 0 or 3(NXDOMAIN)
        val answerCount = if (answerable) 1 else 0

        val header = ByteArray(HEADER_LENGTH)
        writeUShort(header, 0, query.id)
        writeUShort(header, 2, flags)
        writeUShort(header, 4, 1) // QDCOUNT
        writeUShort(header, 6, answerCount) // ANCOUNT
        writeUShort(header, 8, 0) // NSCOUNT
        writeUShort(header, 10, 0) // ARCOUNT

        if (!answerable) {
            return header + questionSection
        }

        val rdata = if (query.queryType == TYPE_A) ByteArray(4) else ByteArray(16)
        // Answer RR: NAME = pointer to offset 0x0C (the question name), then
        // TYPE, CLASS, TTL, RDLENGTH, RDATA.
        val answer = ByteArray(2 + 2 + 2 + 4 + 2 + rdata.size)
        var o = 0
        answer[o++] = 0xC0.toByte()
        answer[o++] = 0x0C.toByte()
        writeUShort(answer, o, query.queryType); o += 2
        writeUShort(answer, o, 1); o += 2 // CLASS IN
        writeUInt(answer, o, 60L); o += 4 // TTL seconds
        writeUShort(answer, o, rdata.size); o += 2
        System.arraycopy(rdata, 0, answer, o, rdata.size)

        return header + questionSection + answer
    }

    /**
     * Returns the smallest TTL (seconds) across the answer records of a
     * response, or null if there are no answers or the message can't be
     * parsed. Used to decide how long a forwarded answer may be cached;
     * returning null simply means "don't cache," so parse failures are safe.
     */
    fun minAnswerTtlSeconds(data: ByteArray, length: Int): Long? {
        if (length < HEADER_LENGTH) return null
        val qdCount = readUShort(data, 4)
        val anCount = readUShort(data, 6)
        if (anCount == 0) return null

        var offset = HEADER_LENGTH
        repeat(qdCount) {
            offset = skipName(data, offset, length) ?: return null
            offset += 4 // qtype + qclass
            if (offset > length) return null
        }

        var minTtl = Long.MAX_VALUE
        repeat(anCount) {
            offset = skipName(data, offset, length) ?: return null
            // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
            if (offset + 10 > length) return null
            val ttl = readUInt(data, offset + 4)
            val rdLength = readUShort(data, offset + 8)
            offset += 10 + rdLength
            if (offset > length) return null
            if (ttl < minTtl) minTtl = ttl
        }
        return if (minTtl == Long.MAX_VALUE) null else minTtl
    }

    /** Advances past a (possibly compressed) DNS name, returning the offset after it. */
    private fun skipName(data: ByteArray, offset: Int, length: Int): Int? {
        var i = offset
        while (i < length) {
            val b = data[i].toInt() and 0xFF
            when {
                b == 0 -> return i + 1
                b and 0xC0 == 0xC0 -> return if (i + 2 <= length) i + 2 else null // compression pointer ends the name
                b and 0xC0 != 0 -> return null // reserved label type
                else -> i += 1 + b
            }
        }
        return null
    }

    private fun readUInt(data: ByteArray, offset: Int): Long =
        ((data[offset].toLong() and 0xFF) shl 24) or
            ((data[offset + 1].toLong() and 0xFF) shl 16) or
            ((data[offset + 2].toLong() and 0xFF) shl 8) or
            (data[offset + 3].toLong() and 0xFF)

    private fun readUShort(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun writeUShort(data: ByteArray, offset: Int, value: Int) {
        data[offset] = ((value shr 8) and 0xFF).toByte()
        data[offset + 1] = (value and 0xFF).toByte()
    }

    private fun writeUInt(data: ByteArray, offset: Int, value: Long) {
        data[offset] = ((value shr 24) and 0xFF).toByte()
        data[offset + 1] = ((value shr 16) and 0xFF).toByte()
        data[offset + 2] = ((value shr 8) and 0xFF).toByte()
        data[offset + 3] = (value and 0xFF).toByte()
    }
}
