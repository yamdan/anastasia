package org.ethtokyo.hackathon.anastasia.core


import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey


class ECKeystoreHelper {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_EC
        private const val EC_CURVE = "secp256r1" // P-256
        private val ECDSA_Q = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        private val ECDSA_Q_HALF = ECDSA_Q.divide(BigInteger.valueOf(2))
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    fun generateKeyPair(alias: String, useStrongBox: Boolean, attestationChallenge: ByteArray? = null): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, ANDROID_KEYSTORE)

        val keyGenParameterSpecBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec(EC_CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(
                attestationChallenge != null && attestationChallenge.size > 0 && useStrongBox
            )

        // 構成証明書を要求する場合はチャレンジを設定
        attestationChallenge?.let { challenge ->
            keyGenParameterSpecBuilder.setAttestationChallenge(challenge)
        }

        val keyGenParameterSpec = keyGenParameterSpecBuilder.build()

        keyPairGenerator.initialize(keyGenParameterSpec)
        return keyPairGenerator.generateKeyPair()
    }

    fun getOrCreteKeyPair(alias: String, useStrongBox: Boolean, attestationChallenge: ByteArray? = null): KeyPair? {
        if (keyExists(alias)) {
            val publicKey = getPublicKey(alias)
            val privateKey = getPrivateKey(alias)
            return KeyPair(publicKey, privateKey)
        }
        return generateKeyPair(alias, useStrongBox, attestationChallenge)
    }

    fun getAttestationCertificate(alias: String): Array<Certificate>? {
        return try {
            keyStore.getCertificateChain(alias)
        } catch (e: Exception) {
            null
        }
    }

    fun deleteEntry(alias: String): Boolean {
        return try {
            keyStore.deleteEntry(alias)
            true
        } catch (e: Exception) {
            false
        }
    }

    fun keyExists(alias: String): Boolean {
        return try {
            keyStore.containsAlias(alias)
        } catch (e: Exception) {
            false
        }
    }

    fun getPrivateKey(alias: String): PrivateKey? {
        return keyStore.getEntry(alias, null)?.let { entry ->
            if (entry is KeyStore.PrivateKeyEntry) {
                entry.privateKey
            } else null
        }
    }

    fun getPublicKey(alias: String): ECPublicKey? {
        return try {
            val certificate = keyStore.getCertificate(alias)
            certificate?.publicKey as? ECPublicKey
        } catch (e: Exception) {
            null
        }
    }

    fun getPublicKeyCoordinates(alias: String): Pair<ByteArray, ByteArray>? {
        val publicKey = getPublicKey(alias) ?: return null
        return extractECPublicKeyCoordinates(publicKey)
    }

    fun sign(signatureAlgorithm: String, alias: String, data: ByteArray): ByteArray {
        val private = getPrivateKey(alias) ?: throw Exception("Private key not found")
        val der = Signature.getInstance(signatureAlgorithm).run {
            initSign(private)
            update(data)
            sign()
        }

        val asn1 = ASN1InputStream(ByteArrayInputStream(der))
        val seq = asn1.readObject() as ASN1Sequence
        val rInt =
            (seq.getObjectAt(0) as ASN1Integer).positiveValue
        val sInt =
            (seq.getObjectAt(1) as ASN1Integer).positiveValue
        val sIntNormalized = if (sInt > ECDSA_Q_HALF) {
            ECDSA_Q.subtract(sInt)
        } else {
            sInt
        }
        val r = bigIntegerToFixedSizeByteArray(rInt, 32)
        val s = bigIntegerToFixedSizeByteArray(sIntNormalized, 32)

        return r + s
    }
}