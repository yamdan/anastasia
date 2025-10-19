package org.ethtokyo.hackathon.anastasia.core


import android.content.Context
import uniffi.mopro.CircuitMeta
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.cert.Certificate


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


fun selectAppropriateCircuit(context: Context, certificate: Certificate): CircuitMeta {
    val prefix = certificate.getCircuitDir()
    // todo: 暗号アルゴリズムごとに適切な回路を使用できるようにすべき
    val vk = getFilePathFromAssets(context, "$prefix/es256.vk")
    val keccak_vk = getFilePathFromAssets(context, "$prefix/es256_keccak.vk")
    val circuit = getFilePathFromAssets(context, "$prefix/es256.json")
    val srs = getFilePathFromAssets(context, "common.srs")
    return CircuitMeta(
        "es256_${prefix.lowercase()}",
        circuit,
        vk,
        keccak_vk,
        srs,
    )
}

fun Certificate.getCircuitDir(): String {
    if (this.isEndEntity()){
        return "ee"
    }
    if (this.isSubroot()){
        return "subroot"
    }
    return "ca"
}