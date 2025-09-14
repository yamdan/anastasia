package org.ethtokyo.hackathon.anastasia.core

import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

class CertificateInfoExtractionTest {

    private val testCertificatePem = """
-----BEGIN CERTIFICATE-----
MIIB1jCCAV2gAwIBAgIUAKPaleRujkV60qOYNtfCM5xBWw8wCgYIKoZIzj0EAwMw
KTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMB4XDTI1
MDgyMjE2MjM0NloXDTI1MTAzMTE2MjM0NVowKTETMBEGA1UEChMKR29vZ2xlIExM
QzESMBAGA1UEAxMJRHJvaWQgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
KcLvJKS+if1RNYkksy440ltknk6W/wtva+IShxv1JieanWtWaCm/Ovj+4FCUP7tw
q/Wxs1rB47iV7i7AqFr70qNjMGEwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQF
MAMBAf8wHQYDVR0OBBYEFP5ibNwq5YDnGWrKI90j8TkCRqilMB8GA1UdIwQYMBaA
FLv4Nq2Jrmzi5Z6U8NWy19J65HxBMAoGCCqGSM49BAMDA2cAMGQCMAF1II8ktm7B
KU6mvr0sh7hL4sbU/3cDI80eIpiC32RYUA1dKPDNGxw5YFrhGQ/yaQIwV/5uJxy0
dvZVx2GWfHKWDghfSNmIeeJ5dpPkIaDinCUAGoR0k70+xyBjdzH1K3yY
-----END CERTIFICATE-----
    """.trimIndent()

    @Test
    fun testExtractCertificateInfo() {
        // PEM証明書をパース
        val certificate = parsePemCertificate(testCertificatePem)

        println("=== Certificate Information Extraction Test ===")
        println()

        // 1. SubjectのDERバイト列
        val subjectDer = certificate.subjectX500Principal.encoded
        println("Subject DER bytes (${subjectDer.size} bytes):")
        println(bytesToHexString(subjectDer))
        println()

        // 2. IssuerのDERバイト列
        val issuerDer = certificate.issuerX500Principal.encoded
        println("Issuer DER bytes (${issuerDer.size} bytes):")
        println(bytesToHexString(issuerDer))
        println()

        // 3. Authority Key Identifierのバイト列
        val authorityKeyIdExtension = certificate.getExtensionValue("2.5.29.35")
        if (authorityKeyIdExtension != null) {
            println("Authority Key Identifier extension found")
            val authorityKeyId = parseAuthorityKeyId(authorityKeyIdExtension)
            println("Authority Key Identifier (${authorityKeyId.size} bytes):")
            println(bytesToHexString(authorityKeyId))
        } else {
            println("Authority Key Identifier extension not found")
        }
        println()

        // 4. Subject Key Identifierのバイト列
        val subjectKeyId = computeSubjectKeyId(certificate)
        println("Subject Key Identifier (${subjectKeyId.size} bytes):")
        println(bytesToHexString(subjectKeyId))
        println()

        // 5. 公開鍵のx, yのバイト列
        val (pubKeyX, pubKeyY) = extractECPublicKeyCoordinates(certificate)
        println("Public Key X coordinate (${pubKeyX.size} bytes):")
        println(bytesToHexString(pubKeyX))
        println()

        println("Public Key Y coordinate (${pubKeyY.size} bytes):")
        println(bytesToHexString(pubKeyY))
        println()

        println("=== Test Complete ===")
    }

    private fun parsePemCertificate(pemData: String): X509Certificate {
        val certData = pemData
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace(Regex("\\s+"), "")

        val certBytes = Base64.getDecoder().decode(certData)
        val certificateFactory = CertificateFactory.getInstance("X.509")
        return certificateFactory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
    }

    private fun bytesToHexString(bytes: ByteArray): String {
        return bytes.joinToString(" ") { String.format("%02x", it.toUByte().toInt()) }
    }

    private fun parseAuthorityKeyId(extensionValue: ByteArray): ByteArray {
        // ASN.1 OCTET STRINGをスキップし、内部のAuthorityKeyIdをパース
        // 簡略化した実装：実際のASN.1パーサーを使用することを推奨
        var offset = 0
        // OCTET STRINGタグをスキップ
        if (extensionValue[offset] == 0x04.toByte()) {
            offset++
            val length = extensionValue[offset].toInt() and 0xFF
            offset++
            if (length > 127) {
                // 長い形式の長さ
                val lengthOfLength = length and 0x7F
                offset += lengthOfLength
            }
        }

        // AuthorityKeyIdのSEQUENCEをスキップ
        if (extensionValue[offset] == 0x30.toByte()) {
            offset += 2 // タグと長さをスキップ
        }

        // keyIdentifier [0] IMPLICIT KeyIdentifierを探す
        if (extensionValue[offset] == 0x80.toByte()) {
            offset++
            val keyIdLength = extensionValue[offset].toInt() and 0xFF
            offset++
            return extensionValue.sliceArray(offset until offset + keyIdLength)
        }

        throw IllegalArgumentException("Authority Key Identifierの解析に失敗しました")
    }
}
