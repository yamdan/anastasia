package com.example.moproapp

import android.util.Log
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.io.File
import uniffi.mopro.CircuitMeta
import uniffi.mopro.generateUserSk
import uniffi.mopro.verifyNoirProof
import uniffi.mopro.proveChainBase64
import uniffi.mopro.proveChainComposedBase64
import uniffi.mopro.setup

fun bytes(vararg ints: Int): ByteArray = ints.map { it.toByte() }.toByteArray()

@Composable
fun NoirComponent() {
    val context = LocalContext.current
    var provingTime by remember { mutableStateOf("") }
    var proofResult by remember { mutableStateOf("") }
    var verificationTime by remember { mutableStateOf("") }
    var verificationResult by remember { mutableStateOf("") }
    var proofBytes by remember { mutableStateOf<ByteArray?>(null) }
    var verificationKey by remember { mutableStateOf<ByteArray?>(null) }

    // Status states
    var isGeneratingProof by remember { mutableStateOf(false) }
    var isVerifyingProof by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf("Ready to generate proof") }

    val srsFile = getFilePathFromAssets("default_20.srs")
    val circuitFile = getFilePathFromAssets("es384_composed/0.1.0/circuit.json")
    val vkFile = getFilePathFromAssets("es384_composed/0.1.0/vk")
    val vkKeccakFile = getFilePathFromAssets("es384_composed/0.1.0/keccak.vk")

    val rootCertFile = getFilePathFromAssets("droid_ca2.der")
    val subrootCertFile = getFilePathFromAssets("droid_ca3.der")
    val caCertFile = getFilePathFromAssets("strongbox.der")
    val eeCertFile = getFilePathFromAssets("keystore.der")

    val userSk by remember { mutableStateOf(generateUserSk()) }

    LaunchedEffect(Unit) {
        setup(srsFile);
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp), contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "ES256 Chain Verification", modifier = Modifier.padding(bottom = 20.dp), fontWeight = FontWeight.Bold, fontSize = 22.sp
            )

            // Status message with prominent styling
            Text(
                text = statusMessage, modifier = Modifier.padding(bottom = 24.dp), textAlign = TextAlign.Center, fontSize = 16.sp, fontWeight = if (isGeneratingProof || isVerifyingProof) FontWeight.Bold else FontWeight.Normal
            )

            // Progress indicator when operations are running
            if (isGeneratingProof || isVerifyingProof) {
                CircularProgressIndicator(
                    modifier = Modifier.padding(bottom = 16.dp)
                )
            }

            Button(
                onClick = {
                    isGeneratingProof = true
                    provingTime = ""
                    proofResult = ""
                    statusMessage = "Generating proof... This may take some time"

                    Thread(
                        Runnable {
                            try {
                                fun readBytes(path: String): ByteArray = File(path).readBytes()
                                val rootCert = readBytes(rootCertFile)
                                val subrootCert = readBytes(subrootCertFile)
                                val caCert = readBytes(caCertFile)
                                val eeCert = readBytes(eeCertFile)

                                val startTime = System.currentTimeMillis()
                                statusMessage = "Generating proof..."
                                val result = proveChainComposedBase64(
                                    CircuitMeta(
                                        "es384_composed/0.1.0",
                                        circuitFile,
                                        vkFile,
                                        vkKeccakFile,
                                        srsFile,
                                    ),
                                    rootCert,
                                    subrootCert,
                                    listOf(caCert),
                                    eeCert,
                                    1757808000, // 2025-09-14T00:00:00Z
                                    userSk,
                                    "https://credential-issuer.example.com",
                                    null
                                )

                                val endTime = System.currentTimeMillis()
                                val duration = endTime - startTime

                                Log.w(null, result.now.toString())
                                Log.w(null, result.nym)
                                Log.w(null, result.proofsAndCommitments)

                                val proofSize = result.proofsAndCommitments.length
                                provingTime = "Proving time: $duration ms"
                                proofResult = "Proof generated: $proofSize bytes (base64url-encoded)"
                                statusMessage = "Proof generation completed with nym = ${result.nym}"
                            } catch (e: Exception) {
                                provingTime = "Proving failed"
                                proofResult = "Error: ${e.message}"
                                statusMessage = "Proof generation failed"
                                e.printStackTrace()
                            } finally {
                                isGeneratingProof = false
                            }
                        }).start()
                }, modifier = Modifier.padding(top = 20.dp), enabled = !isGeneratingProof && !isVerifyingProof
            ) {
                Text(text = "Generate Proof")
            }

            Spacer(modifier = Modifier.height(16.dp))

            Button(
                onClick = {
                    isVerifyingProof = true
                    verificationTime = ""
                    verificationResult = ""
                    statusMessage = "Verifying proof..."

                    Thread(
                        Runnable {
                            try {
                                proofBytes?.let { proof ->
                                    verificationKey?.let { vk ->
                                        val onChain = true  // Use Keccak for Solidity compatibility
                                        val lowMemoryMode = false

                                        val startTime = System.currentTimeMillis()
                                        val result = verifyNoirProof(
                                            circuitFile, proof, onChain, vk, lowMemoryMode
                                        )
                                        val endTime = System.currentTimeMillis()
                                        val duration = endTime - startTime

                                        verificationTime = "Verification time: $duration ms"
                                        verificationResult = "Verification result: $result"
                                        if (result) statusMessage = "Proof verified successfully!"
                                        else statusMessage = "Proof verification failed!"
                                    } ?: run {
                                        verificationResult = "No verification key available"
                                        statusMessage = "Please generate a proof first to get verification key"
                                    }
                                } ?: run {
                                    verificationResult = "No proof available"
                                    statusMessage = "Please generate a proof first"
                                }
                            } catch (e: Exception) {
                                verificationTime = "Verification failed"
                                verificationResult = "Error: ${e.message}"
                                statusMessage = "Proof verification error"
                                e.printStackTrace()
                            } finally {
                                isVerifyingProof = false
                            }
                        }).start()
                }, modifier = Modifier.padding(top = 20.dp), enabled = !isGeneratingProof && !isVerifyingProof && proofBytes != null
            ) {
                Text(text = "Verify Proof")
            }

            Spacer(modifier = Modifier.height(40.dp))

            // Results displayed in a more organized way
            if (provingTime.isNotEmpty() || proofResult.isNotEmpty() || verificationTime.isNotEmpty() || verificationResult.isNotEmpty()) {

                Text(
                    text = "Results", fontWeight = FontWeight.Bold, fontSize = 18.sp, modifier = Modifier.padding(bottom = 8.dp)
                )

                if (provingTime.isNotEmpty()) {
                    Text(
                        text = provingTime, modifier = Modifier
                            .padding(top = 4.dp)
                            .width(280.dp), textAlign = TextAlign.Center
                    )
                }

                if (proofResult.isNotEmpty()) {
                    Text(
                        text = proofResult, modifier = Modifier
                            .padding(top = 4.dp)
                            .width(280.dp), textAlign = TextAlign.Center
                    )
                }

                if (verificationTime.isNotEmpty()) {
                    Text(
                        text = verificationTime, modifier = Modifier
                            .padding(top = 4.dp)
                            .width(280.dp), textAlign = TextAlign.Center
                    )
                }

                if (verificationResult.isNotEmpty()) {
                    Text(
                        text = verificationResult, modifier = Modifier
                            .padding(top = 4.dp)
                            .width(280.dp), textAlign = TextAlign.Center, fontWeight = if (verificationResult.contains("true")) FontWeight.Bold else FontWeight.Normal
                    )
                }
            }
        }
    }
}