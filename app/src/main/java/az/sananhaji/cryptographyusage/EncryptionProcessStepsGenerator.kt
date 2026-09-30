package az.sananhaji.cryptographyusage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object EncryptionProcessStepsGenerator {

    // It's used as private key anchor for keystore
    private const val MOBILE_ALIAS = "MOBILE_ALIAS"
    private const val KEYSTORE_TYPE = "AndroidKeyStore"
    private const val EC_GEN_PARAMETER_SPEC_STD_NAME = "secp256r1"
    private const val BACKEND_KEY_PAIR_GENERATOR_ALGORITHM = "EC"
    private const val AGREEMENT_ALGORITHM = "ECDH"

    var backendKeyPair: KeyPair? = null

    fun startProcess(): List<String> {
        val message = "Message for Sanan"

        val steps = mutableListOf<String>()
        steps.add("Message: $message")

        val mobilePublicKey = generatePublicKeyForMobile()
        steps.add("Mobile Public key yaradildi : $mobilePublicKey | Mobile Public key backende gonderdi ".trimMargin())

        val backendPublicKey = generatePublicKeyForBackend()
        steps.add("Backend Public key yaradildi : $backendPublicKey | Backend Public key mobileye gonderdi".trimMargin())

        val mobileSharedSecret = generateSharedSecretForMobile(backendPublicKey)
        steps.add("Mobile Shared secret yaradildi : $mobileSharedSecret Mobile Shared secret backende GONDERILMIR".trimMargin())

        val backendSharedSecret = generateSharedSecretForBackend(mobilePublicKey)
        steps.add("Backend Shared secret yaradildi : $backendSharedSecret | Backend Shared secret Mobile GONDERILMIR ".trimMargin())

        val pair = encryptMessageInMobile(message, mobileSharedSecret)
        val ivMobile = pair.first
        val cipherTextMobile = pair.second
        steps.add("iv: $ivMobile | cipherTextMobile: $cipherTextMobile | mobile backende gonderir ".trimMargin())

        val decryptedMessage = decryptMessageInBackend(cipherTextMobile, ivMobile, backendSharedSecret)
        steps.add("decryptedMessage: $decryptedMessage | backend messageni gorur ".trimMargin())

        return steps
    }

    private fun generatePublicKeyForMobile(): String {
        val keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
        keyStore.load(null)
        if (keyStore.containsAlias(MOBILE_ALIAS)) keyStore.deleteEntry(MOBILE_ALIAS)

        val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_TYPE)
        val keyGenParameterSpecBuilder = KeyGenParameterSpec.Builder(MOBILE_ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
        val ecGenParameterSpec = ECGenParameterSpec(EC_GEN_PARAMETER_SPEC_STD_NAME)
        keyGenParameterSpecBuilder.setAlgorithmParameterSpec(ecGenParameterSpec)
        val keyGenParameterSpec = keyGenParameterSpecBuilder.build()

        keyPairGenerator.initialize(keyGenParameterSpec)

        val mobileKeyPair = keyPairGenerator.generateKeyPair()
        val mobilePublicKey = byteArrayToBase64(mobileKeyPair.public.encoded)
        return mobilePublicKey
    }

    private fun generatePublicKeyForBackend(): String {
        val keyPairGenerator = KeyPairGenerator.getInstance(BACKEND_KEY_PAIR_GENERATOR_ALGORITHM)
        val ecGenParameterSpec = ECGenParameterSpec(EC_GEN_PARAMETER_SPEC_STD_NAME)
        keyPairGenerator.initialize(ecGenParameterSpec)

        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = byteArrayToBase64(keyPair.public.encoded)
        backendKeyPair = keyPair

        return publicKey
    }

    private fun generateSharedSecretForMobile(backendPublicKey: String): String {
        val keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
        keyStore.load(null)
        val mobilePrivateKey = keyStore.getKey(MOBILE_ALIAS, null) as PrivateKey

        val mobileAgreement = KeyAgreement.getInstance(AGREEMENT_ALGORITHM)
        mobileAgreement.init(mobilePrivateKey)

        val backendPublicKeyBase64 = base64ToByteArray(backendPublicKey)
        val keyFactor = KeyFactory.getInstance(BACKEND_KEY_PAIR_GENERATOR_ALGORITHM)
        val backendPublicKey = keyFactor.generatePublic(X509EncodedKeySpec(backendPublicKeyBase64))
        mobileAgreement.doPhase(backendPublicKey, true)

        val messageDigest = MessageDigest.getInstance("SHA-256")
        val agreementSecret = mobileAgreement.generateSecret()
        val mobileAESKeyBytes = messageDigest.digest(agreementSecret)
        val sharedSecret = byteArrayToBase64(mobileAESKeyBytes)

        return sharedSecret
    }

    private fun generateSharedSecretForBackend(mobilePublicKey: String): String {
        val agreement = KeyAgreement.getInstance(AGREEMENT_ALGORITHM)
        agreement.init(backendKeyPair!!.private)

        val publicKeyBase64 = base64ToByteArray(mobilePublicKey)
        val keyFactor = KeyFactory.getInstance(BACKEND_KEY_PAIR_GENERATOR_ALGORITHM)
        val mobilePublicKey = keyFactor.generatePublic(X509EncodedKeySpec(publicKeyBase64))
        agreement.doPhase(mobilePublicKey, true)

        val messageDigest = MessageDigest.getInstance("SHA-256")
        val agreementSecret = agreement.generateSecret()
        val backendAESKeyBytes = messageDigest.digest(agreementSecret)
        val sharedSecret = byteArrayToBase64(backendAESKeyBytes)

        return sharedSecret
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

    private fun byteArrayToBase64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun base64ToByteArray(base64: String): ByteArray =
        Base64.decode(base64, Base64.NO_WRAP)

}