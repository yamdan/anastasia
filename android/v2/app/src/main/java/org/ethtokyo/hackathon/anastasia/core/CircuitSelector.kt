package org.ethtokyo.hackathon.anastasia.core


import android.content.Context
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.cert.Certificate
import java.security.cert.X509Certificate

data class Circuit(
    val vk: String,
    val circuit: String,
    val srs: String
)

private val assetFileCache = mutableMapOf<String, String>()

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


fun selectAppropriateCircuit(context: Context, certificate: Certificate): Circuit {
    val prefix = certificate.getCircuitDir()

    // todo: 暗号アルゴリズムごとに適切な回路を使用できるようにすべき
    return Circuit(
        vk = getFilePathFromAssets(context, "$prefix/es256.vk"),
        circuit = getFilePathFromAssets(context, "$prefix/es256.json"),
        srs = getFilePathFromAssets(context, "$prefix/common.srs")
    )
}

fun Certificate.isEndEntity(): Boolean {
    try {
        val x509Cert = this as X509Certificate
        val issuer = x509Cert.issuerX500Principal
        val issuerName = issuer.name

        // IssuerのDNからO（Organization）フィールドを抽出
        val oValue = extractOrganizationFromDN(issuerName)

        // Oの値を小文字に正規化してチェック
        val normalizedO = oValue?.lowercase()
        return (normalizedO == "tee" || normalizedO == "strongbox")
    }catch(_: Exception){
        return false
    }
}

fun Certificate.getCircuitDir(): String {
    if (this.isEndEntity()){
        return "ee_long"
    }
    return "ca"
}

private fun extractOrganizationFromDN(dn: String): String? {
    // DN（Distinguished Name）からO=の値を抽出
    val regex = Regex("(?:^|,)\\s*O\\s*=\\s*([^,]+)", RegexOption.IGNORE_CASE)
    val matchResult = regex.find(dn)
    return matchResult?.groupValues?.get(1)?.trim()
}