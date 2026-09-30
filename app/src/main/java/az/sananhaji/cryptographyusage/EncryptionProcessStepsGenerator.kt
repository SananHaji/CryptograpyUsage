package az.sananhaji.cryptographyusage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.compose.material3.SnackbarData
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object EncryptionProcessStepsGenerator {

    // It's used as private key anchor for keystore
    private const val MOBILE_ALIAS = "MOBILE_ALIAS"
    private const val KEYSTORE_TYPE = "AndroidKeyStore"
    private const val EC_GEN_PARAMETER_SPEC_STD_NAME = "secp256r1"
    private const val BACKEND_KEY_PAIR_GENERATOR_ALGORITHM = "EC"
    private const val AGREEMENT_ALGORITHM = "ECDH"
    const val HKDF_SALT_LENGTH_BYTES = 32
    private val HKDF_INFO = "CryptographyUsage|ECDH-P256|HKDF-SHA256|AES-256-GCM|v1".toByteArray()
    private const val AES_KEY_LENGTH_BYTES = 32


    var backendKeyPair: KeyPair? = null

    fun startProcess(): List<Message> {
        val message = "Message for Sanan"

        val steps = mutableListOf<Message>()
        steps.add(
            Message(
                title = "Proses basladi",
                description = "mesaj backende securely gonderilmelidir",
                properties = listOf(
                    Property("Message: ", message)
                )
            )
        )

        val mobilePublicKey = generatePublicKeyForMobile()
        steps.add(
            Message(
                title = "Mobile Public key yaradildi",
                description = "Mobile Public key backende gonderdi",
                properties = listOf(
                    Property("mobilePublicKey: ", mobilePublicKey),
                )
            )
        )

        val backendPublicKey = generatePublicKeyForBackend()
        steps.add(
            Message(
                title = "Backend Public key yaradildi",
                description = "Backend Public keyi mobileye gonderdi",
                properties = listOf(
                    Property("backendPublicKey: ", backendPublicKey),
                )
            )
        )

        val (salt, mobileSharedSecret) = generateSharedSecretForMobile(backendPublicKey)
        steps.add(
            Message(
                title = "Mobile shared secret yaradildi",
                description = "backende mobileSharedSecret gonderilmir, salt gonderilir backende mobilePublicKey ile",
                properties = listOf(
                    Property("mobileSharedSecret: ", mobileSharedSecret),
                    Property("salt: ", salt),
                )
            )
        )

        val backendSharedSecret = generateSharedSecretForBackend(mobilePublicKey, salt)
        steps.add(
            Message(
                title = "Backend shared secret yaradildi",
                description = "mobile backendSharedSecret gonderilmir",
                properties = listOf(
                    Property("backendSharedSecret: ", backendSharedSecret),
                )
            )
        )


        val (iv, cipherText) = encryptMessageInMobile(message, mobileSharedSecret)
        steps.add(
            Message(
                title = "Mobilde encrypt olundu mesaj",
                description = "iv ve cipherText backende gonderilir",
                properties = listOf(
                    Property("iv: ", iv),
                    Property("cipherText: ", cipherText),
                )
            )
        )

        val encryptedMessage = decryptMessageInBackend(cipherText, iv, backendSharedSecret)
        steps.add(
            Message(
                title = "Backendde message decrypt olundu",
                properties = listOf(
                    Property("encryptedMessage: ", encryptedMessage),
                )
            )
        )


        steps.add(Message(title = "Proses ugurla basa catdi"))

        return steps
    }

    private fun generatePublicKeyForMobile(): String {
        val keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
        keyStore.load(null)
        if (keyStore.containsAlias(MOBILE_ALIAS)) keyStore.deleteEntry(MOBILE_ALIAS)

        val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_TYPE)
        val keyGenParameterSpec =
            KeyGenParameterSpec.Builder(MOBILE_ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_GEN_PARAMETER_SPEC_STD_NAME))
                .build()

        keyPairGenerator.initialize(keyGenParameterSpec)

        val mobileKeyPair = keyPairGenerator.generateKeyPair()
        return byteArrayToBase64(mobileKeyPair.public.encoded)
    }

    private fun generatePublicKeyForBackend(): String {
        val keyPairGenerator = KeyPairGenerator.getInstance(BACKEND_KEY_PAIR_GENERATOR_ALGORITHM)
        keyPairGenerator.initialize(ECGenParameterSpec(EC_GEN_PARAMETER_SPEC_STD_NAME))

        val keyPair = keyPairGenerator.generateKeyPair()
        backendKeyPair = keyPair

        return byteArrayToBase64(keyPair.public.encoded)
    }

    private fun generateSharedSecretForMobile(backendPublicKey: String): Pair<String, String> {
        val keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
        keyStore.load(null)
        val mobilePrivateKey = keyStore.getKey(MOBILE_ALIAS, null) as PrivateKey

        val mobileAgreement = KeyAgreement.getInstance(AGREEMENT_ALGORITHM)
        mobileAgreement.init(mobilePrivateKey)

        val backendPublicKey = base64ToPublicKey(backendPublicKey)
        mobileAgreement.doPhase(backendPublicKey, true)

        val salt = HmacAlgorithms.generateHkdfSalt()
        val agreementSecret = mobileAgreement.generateSecret()
        val pseudoRandomKey = HmacAlgorithms.hkdfExtract(base64ToByteArray(salt), agreementSecret)
        val aesKey = HmacAlgorithms.hkdfExpand(pseudoRandomKey, HKDF_INFO, AES_KEY_LENGTH_BYTES)

        return salt to byteArrayToBase64(aesKey)
    }


    private fun generateSharedSecretForBackend(mobilePublicKey: String, salt: String): String {
        val agreement = KeyAgreement.getInstance(AGREEMENT_ALGORITHM)
        agreement.init(backendKeyPair!!.private)

        val mobilePublicKey = base64ToPublicKey(mobilePublicKey)
        agreement.doPhase(mobilePublicKey, true)

        val agreementSecret = agreement.generateSecret()

        val pseudoRandomKey = HmacAlgorithms.hkdfExtract(base64ToByteArray(salt), agreementSecret)
        val aesKey = HmacAlgorithms.hkdfExpand(pseudoRandomKey, HKDF_INFO, AES_KEY_LENGTH_BYTES)

        return byteArrayToBase64(aesKey)
    }

    private fun encryptMessageInMobile(message: String, mobileSecretKey: String): Pair<String, String> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        val mobileAESKeyBytes = base64ToByteArray(mobileSecretKey)
        val mobileSecretKeySpec = SecretKeySpec(mobileAESKeyBytes, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, mobileSecretKeySpec)

        val iv = byteArrayToBase64(cipher.iv)
        val encryptedText = byteArrayToBase64(cipher.doFinal(message.toByteArray()))

        return iv to encryptedText
    }


    private fun decryptMessageInBackend(cipherText: String, iv: String, backendSharedSecret: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        val backendAESKeyBytes = base64ToByteArray(backendSharedSecret)
        val backendSecretKeySpec = SecretKeySpec(backendAESKeyBytes, "AES")
        val backendGCMParameterSpec = GCMParameterSpec(128, base64ToByteArray(iv))
        cipher.init(Cipher.DECRYPT_MODE, backendSecretKeySpec, backendGCMParameterSpec)

        val decryptedText = String(cipher.doFinal(base64ToByteArray(cipherText)))

        return decryptedText
    }

    private fun base64ToPublicKey(backendPublicKeyBase64: String): PublicKey {
        val keyFactor = KeyFactory.getInstance(BACKEND_KEY_PAIR_GENERATOR_ALGORITHM)
        return keyFactor.generatePublic(X509EncodedKeySpec(base64ToByteArray(backendPublicKeyBase64)))
    }

    fun byteArrayToBase64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun base64ToByteArray(base64: String): ByteArray =
        Base64.decode(base64, Base64.NO_WRAP)

}