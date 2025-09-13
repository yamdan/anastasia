package com.example.moproapp

import org.junit.Test
import org.junit.Assert.*
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Security
import java.util.Date
import javax.security.auth.x500.X500Principal

import kotlin.io.encoding.*
import java.util.Base64
import kotlin.io.encoding.ExperimentalEncodingApi


class X509ParserTest {

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Test
    fun testParseCertificate() {
        val parser = X509Parser()

        // 実際のテスト用証明書を生成（簡単な自己署名証明書）
        val certBytes = generateTestCertificate()
        val result = parser.parse(certBytes)

        // 基本的な結果の検証
        println("=== === target data === ===")
        val encodedCert = Base64.getEncoder().encodeToString(certBytes)
        println(
           encodedCert
        )

        println("=== === parsed data === ===")
        println(result)

        assertNotNull(result)
        assertNotNull(result.issuer)
        assertNotNull(result.subject)
        assertNotNull(result.signature)
        assertNotNull(result.publicKey)
        assertNotNull(result.signatureAlgorithm)

        // 署名値とパブリックキーは空ではないはず
        assertTrue(result.signature.isNotEmpty())
        assertNotNull(result.publicKey.algorithm)
        assertNotNull(result.publicKey.encoded)
        assertTrue(result.publicKey.encoded.isNotEmpty())

        // 署名アルゴリズムの検証（SHA256WithRSAを期待）
        assertTrue(result.signatureAlgorithm.contains("1.2.840.113549.1.1.11")) // SHA256WithRSA OID
    }

    @Test
    fun testParseInvalidCertificate() {
        val parser = X509Parser()
        val invalidBytes = byteArrayOf(0x01, 0x02, 0x03)

        try {
            parser.parse(invalidBytes)
            fail("無効な証明書データでは例外が発生するべき")
        } catch (e: Exception) {
            // 期待される動作
            assertTrue(true)
        }
    }

    private fun generateTestCertificate(): ByteArray {
        // RSAキーペアを生成
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()

        // 証明書の情報を設定
        val issuer = X500Principal("CN=Test CA, O=Test Organization, C=US")
        val subject = X500Principal("CN=Test CA, O=Test Organization, C=US") // 自己署名
        val serialNumber = BigInteger.valueOf(1)
        val notBefore = Date()
        val notAfter = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000) // 1年後

        // 証明書ビルダーを作成
        val certBuilder = JcaX509v3CertificateBuilder(
            issuer,
            serialNumber,
            notBefore,
            notAfter,
            subject,
            keyPair.public
        )

        // コンテンツサイナーを作成
        val contentSigner = JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(keyPair.private)

        // 証明書を生成
        val certHolder = certBuilder.build(contentSigner)

        return certHolder.encoded
    }
}