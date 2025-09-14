package org.ethtokyo.hackathon.anastasia.core


import android.content.Context
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

data class Circuit(
    val vk: ByteArray,
    val circuit: String,
    val srs: String
) {
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


fun selectAppropriateCircuit(context: Context, certificate: X509ParseResult): Circuit {
    val circuitDir = getCircuitDir(certificate)

    return Circuit(
        vk = loadAssetBinaryData(context, "$circuitDir/verify_ecdsa.vk"),
        circuit = getFilePathFromAssets(context, "$circuitDir/verify_ecdsa.json"),
        srs = getFilePathFromAssets(context, "$circuitDir/verify_ecdsa.srs")
    )
}


fun getCircuitDir(certificate: X509ParseResult): String {
    // todo: 証明書の構造を見て適切なサーキット名を返却する
    return "circuit1"
}