package org.ethtokyo.hackathon.anastasia.core

import android.content.Context
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import org.junit.Test
import org.junit.Before
import org.junit.After
import java.io.ByteArrayInputStream
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.Base64
import kotlin.test.assertNotNull

class ProverTest {

    private lateinit var mockContext: Context

    @Before
    fun setUp() {
        mockContext = mockk<Context>(relaxed = true)

        // selectAppropriateCircuit関数をスタティックにモック
        mockkStatic("org.ethtokyo.hackathon.anastasia.core.CircuitSelectorKt")
        every { selectAppropriateCircuit(any(), any()) } returns Circuit(
            vk = "/mock/path/circuit.vk",
            circuit = "/mock/path/circuit.json",
            srs = "/mock/path/common.srs"
        )

        // prove関数もモック
        mockkStatic("uniffi.mopro.MoproKt")
        val mockProofResult = mockk<uniffi.mopro.ProofResult>(relaxed = true)
        every { uniffi.mopro.prove(any(), any(), any(), any(), any(), any(), any()) } returns mockProofResult
    }

    @After
    fun tearDown() {
        unmockkStatic("org.ethtokyo.hackathon.anastasia.core.CircuitSelectorKt")
        unmockkStatic("uniffi.mopro.MoproKt")
    }

    @Test
    fun testProveParentChildRel() {
        // テスト用証明書データ
        val childCertPem = """
            -----BEGIN CERTIFICATE-----
            MIIB3zCCAYSgAwIBAgIQQvetP46myG9iTwJUbolpXTAKBggqhkjOPQQDAjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwHhcNMjUwODE2MDkzMzQwWhcNMjUwOTE1MDQwNDMyWjA5MSkwJwYDVQQDEyA0MmY3YWQzZjhlYTZjODZmNjI0ZjAyNTQ2ZTg5Njk1ZDEMMAoGA1UEChMDVEVFMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH88NDZL830j8Hphr+uyr6HE3Hoz1ubD94LfRWTW3wVGzkvxWzr6Dj58smDrX3vEzlOeBOfLW4rtAiT19168u5aN+MHwwHQYDVR0OBBYEFAU2N5IqenydpSl8wZI3gK1UH4dvMB8GA1UdIwQYMBaAFKKRHWQmS9469q7vyp2oKlCYLYZeMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMBkGCisGAQQB1nkCAR4EC6IBEANmR29vZ2xlMAoGCCqGSM49BAMCA0kAMEYCIQC14FLeR/NmDYThQtgYVgLE3b6xHJ6HNcPC2j4w0i/8xAIhAPxsMYGIPpN2OQwKGdHFzp/MFBmJnj4ce5k7IqRx+39z
            -----END CERTIFICATE-----
        """.trimIndent()

        val parentCertPem = """
            -----BEGIN CERTIFICATE-----
            MIIB1jCCAV2gAwIBAgIUAJ7VjHfw/KwtOc0aHXL0VbRqe8UwCgYIKoZIzj0EAwMwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMB4XDTI1MDgxNzIyMzEwOFoXDTI1MTAyNjIyMzEwN1owKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4hxkUuFiNE9dtMSz+zZkWkersfdcZSWR1dNLwumpWHlSfVzlwKEIGin3ZWPMjAKhmC6t5AEJQFTTo1cxbqYQnqNjMGEwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFKKRHWQmS9469q7vyp2oKlCYLYZeMB8GA1UdIwQYMBaAFLv4Nq2Jrmzi5Z6U8NWy19J65HxBMAoGCCqGSM49BAMDA2cAMGQCME5dRrUSl9ER4aYqgYlMAOj+55hYvLGykR57DAQBoqC1B1X8DGZNzXoc+nd4Bza5AwIwFiOA9UI0rWbvBcnv6g5u4dAxt3faprvHRs/6CDNOMVWhsGNs59Ln1yfX6p9aBbq+
            -----END CERTIFICATE-----
        """.trimIndent()

        // PEM形式からCertificateオブジェクトを生成
        val childCert = parsePemCertificate(childCertPem)
        val parentCert = parsePemCertificate(parentCertPem)

        // テスト用パラメータ
        val caPrevCmt = "0ede28f511104f08069e07986707873be5cbba917f02f02407ad1fdd6838679b"
        val caPrevCmtR = "deadbeef"

        // proveParentChildRel関数をテスト実行
        try {
            val result = proveParentChildRel(mockContext, childCert, parentCert, caPrevCmt, caPrevCmtR)

            // 結果が返されることを確認
            assertNotNull(result, "ProofResult should not be null")

            println("テスト成功: ProofResultが正常に返されました")
            println("Result: $result")

        } catch (e: Exception) {
            // エラーの詳細を表示
            println("テスト中にエラーが発生しました: ${e.message}")
            e.printStackTrace()
            throw e
        }
    }

    @Test
    fun testCertificateDataExtraction() {
        // 証明書データの抽出機能をテスト
        val childCertPem = """
            -----BEGIN CERTIFICATE-----
            MIIB3zCCAYSgAwIBAgIQQvetP46myG9iTwJUbolpXTAKBggqhkjOPQQDAjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwHhcNMjUwODE2MDkzMzQwWhcNMjUwOTE1MDQwNDMyWjA5MSkwJwYDVQQDEyA0MmY3YWQzZjhlYTZjODZmNjI0ZjAyNTQ2ZTg5Njk1ZDEMMAoGA1UEChMDVEVFMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH88NDZL830j8Hphr+uyr6HE3Hoz1ubD94LfRWTW3wVGzkvxWzr6Dj58smDrX3vEzlOeBOfLW4rtAiT19168u5aN+MHwwHQYDVR0OBBYEFAU2N5IqenydpSl8wZI3gK1UH4dvMB8GA1UdIwQYMBaAFKKRHWQmS9469q7vyp2oKlCYLYZeMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMBkGCisGAQQB1nkCAR4EC6IBEANmR29vZ2xlMAoGCCqGSM49BAMCA0kAMEYCIQC14FLeR/NmDYThQtgYVgLE3b6xHJ6HNcPC2j4w0i/8xAIhAPxsMYGIPpN2OQwKGdHFzp/MFBmJnj4ce5k7IqRx+39z
            -----END CERTIFICATE-----
        """.trimIndent()

        val parentCertPem = """
            -----BEGIN CERTIFICATE-----
            MIIB1jCCAV2gAwIBAgIUAJ7VjHfw/KwtOc0aHXL0VbRqe8UwCgYIKoZIzj0EAwMwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMB4XDTI1MDgxNzIyMzEwOFoXDTI1MTAyNjIyMzEwN1owKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4hxkUuFiNE9dtMSz+zZkWkersfdcZSWR1dNLwumpWHlSfVzlwKEIGin3ZWPMjAKhmC6t5AEJQFTTo1cxbqYQnqNjMGEwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFKKRHWQmS9469q7vyp2oKlCYLYZeMB8GA1UdIwQYMBaAFLv4Nq2Jrmzi5Z6U8NWy19J65HxBMAoGCCqGSM49BAMDA2cAMGQCME5dRrUSl9ER4aYqgYlMAOj+55hYvLGykR57DAQBoqC1B1X8DGZNzXoc+nd4Bza5AwIwFiOA9UI0rWbvBcnv6g5u4dAxt3faprvHRs/6CDNOMVWhsGNs59Ln1yfX6p9aBbq+
            -----END CERTIFICATE-----
        """.trimIndent()

        val childCert = parsePemCertificate(childCertPem)
        val parentCert = parsePemCertificate(parentCertPem)

        // 各種データ抽出機能をテスト
        try {
            // DERエンコードデータの取得をテスト
            val derData = parentCert.encoded
            assertNotNull(derData, "DER encoded data should not be null")
            println("Parent certificate DER data length: ${derData.size} bytes")

            // 回路選択機能をテスト
            val circuit = selectAppropriateCircuit(mockContext, childCert)
            assertNotNull(circuit, "Selected circuit should not be null")
            println("Selected circuit: $circuit")

            println("証明書データ抽出テストが成功しました")

        } catch (e: Exception) {
            println("証明書データ抽出テスト中にエラーが発生しました: ${e.message}")
            e.printStackTrace()
            throw e
        }
    }

    /**
     * PEM形式の証明書文字列をCertificateオブジェクトに変換するヘルパー関数
     */
    private fun parsePemCertificate(pemData: String): Certificate {
        val certData = pemData
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\\s+".toRegex(), "")

        val certBytes = Base64.getDecoder().decode(certData)
        val certFactory = CertificateFactory.getInstance("X.509")

        return certFactory.generateCertificate(ByteArrayInputStream(certBytes))
    }
}