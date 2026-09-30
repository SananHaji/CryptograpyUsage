package az.sananhaji.cryptographyusage

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import az.sananhaji.cryptographyusage.EncryptionProcessStepsGenerator.HKDF_SALT_LENGTH_BYTES
import az.sananhaji.cryptographyusage.EncryptionProcessStepsGenerator.byteArrayToBase64
import java.security.SecureRandom
import kotlin.math.min

object HmacAlgorithms {
    private const val HMAC_ALGORITHM = "HmacSHA256"


    fun hkdfExtract(salt: ByteArray, input: ByteArray): ByteArray =
        hmacSha256(salt, input)

    fun hkdfExpand(pseudoRandomKey: ByteArray, input: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * HKDF_SALT_LENGTH_BYTES) { "HKDF outputu rangeni asir $length" }

        val outputKey = ByteArray(length)
        var previousBlock = ByteArray(0)
        var offset = 0
        var counter = 1

        while (offset < length) {
            val block = hmacSha256(pseudoRandomKey, previousBlock + input + counter.toByte())
            previousBlock.fill(0)
            val count = minOf(block.size, length - offset)
            System.arraycopy(block, 0, outputKey, offset, count)
            offset += count
            counter++
            previousBlock = block
        }
        previousBlock.fill(0)

        return outputKey
    }


    fun generateHkdfSalt(): String {
        val salt = ByteArray(HKDF_SALT_LENGTH_BYTES)
        SecureRandom().nextBytes(salt)
        return byteArrayToBase64(salt)
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
        return mac.doFinal(data)
    }

}