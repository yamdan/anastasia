package org.ethtokyo.hackathon.anastasia.core


import android.content.Context
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

data class Circuit(
    val vk: String,
    val circuit: String,
    val srs: String
)
/*
{

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Circuit

        if (!vk.contentEquals(other.vk)) return false
        if (circuit != other.circuit) return false
        if (srs != other.srs) return false

        return true
    }

    override fun hashCode(): Int {
        var result = vk.contentHashCode()
        result = 31 * result + circuit.hashCode()
        result = 31 * result + srs.hashCode()
        return result
    }
}
 */

private val assetFileCache = mutableMapOf<String, String>()
private val assetBinaryCache = mutableMapOf<String, ByteArray>()

@Throws(IOException::class)
private fun copyFileInternal(inputStream: InputStream, outputStream: OutputStream) {
    val buffer = ByteArray(1024)
    var read: Int
    while (inputStream.read(buffer).also { read = it } != -1) {
        outputStream.write(buffer, 0, read)
    }
}

fun getFilePathFromAssets(context: Context, assetFileName: String): String {
    // キャッシュに存在し、ファイルも実際に存在する場合は既存のパスを返却
    assetFileCache[assetFileName]?.let { cachedPath ->
        if (File(cachedPath).exists()) {
            return cachedPath
        } else {
            // キャッシュにあるがファイルが削除されている場合はキャッシュを削除
            assetFileCache.remove(assetFileName)
        }
    }

    // ファイルが存在しない場合のみコピーを実行
    val assetManager = context.assets
    val inputStream = assetManager.open(assetFileName)
    val file = File(context.filesDir, assetFileName)

    file.parentFile?.let { parentDir ->
        if (!parentDir.exists()) {
            parentDir.mkdirs()
        }
    }

    copyFileInternal(inputStream, file.outputStream())
    inputStream.close()

    val absolutePath = file.absolutePath
    // キャッシュに保存
    assetFileCache[assetFileName] = absolutePath

    return absolutePath
}

fun loadAssetBinaryData(context: Context, assetFileName: String): ByteArray {
    // キャッシュに存在する場合は既存のデータを返却
    if (assetBinaryCache.containsKey(assetFileName)) {
        val cached = assetBinaryCache[assetFileName]
        if (cached != null) {
            return cached
        }
    }

    val data = context.assets.open(assetFileName).readBytes()

    assetBinaryCache[assetFileName] = data
    return data
}


fun selectAppropriateCircuit(context: Context, certificate: Certificate): Circuit {
    val prefix = getCircuitDir(certificate)

    return Circuit(
        vk = getFilePathFromAssets(context, "$prefix/es256_${prefix}.vk"),
        circuit = getFilePathFromAssets(context, "$prefix/es256_${prefix}.json"),
        srs = getFilePathFromAssets(context, "$prefix/common.srs")
    )
}


fun getCircuitDir(certificate: Certificate): String {
    try {
        val x509Cert = certificate as X509Certificate
        val issuer = x509Cert.issuerX500Principal
        val issuerName = issuer.name

        // IssuerのDNからO（Organization）フィールドを抽出
        val oValue = extractOrganizationFromDN(issuerName)

        // Oの値を小文字に正規化してチェック
        val normalizedO = oValue?.lowercase()

        return if (normalizedO == "tee" || normalizedO == "strongbox") {
            "ee"
        } else {
            "ca"
        }
    } catch (_: Exception) {
        // 証明書の処理でエラーが発生した場合はデフォルトとして "ca" を返却
        return "ca"
    }
}

private fun extractOrganizationFromDN(dn: String): String? {
    // DN（Distinguished Name）からO=の値を抽出
    val regex = Regex("(?:^|,)\\s*O\\s*=\\s*([^,]+)", RegexOption.IGNORE_CASE)
    val matchResult = regex.find(dn)
    return matchResult?.groupValues?.get(1)?.trim()
}