package com.example.moproapp

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
import uniffi.mopro.generateNoirProof
import uniffi.mopro.verifyNoirProof
import uniffi.mopro.getNoirVerificationKey

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

    val circuitFile = getFilePathFromAssets("verify_ecdsa.json")
    val srsFile = getFilePathFromAssets("verify_ecdsa.srs")

    // Load existing verification key from assets
    val existingVk = remember {
        try {
            context.assets.open("verify_ecdsa.vk").readBytes()
        } catch (e: Exception) {
            null
        }
    }


    Box(modifier = Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "ECDSA Verification",
                modifier = Modifier.padding(bottom = 20.dp),
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp
            )

            // Status message with prominent styling
            Text(
                text = statusMessage,
                modifier = Modifier.padding(bottom = 24.dp),
                textAlign = TextAlign.Center,
                fontSize = 16.sp,
                fontWeight = if (isGeneratingProof || isVerifyingProof) FontWeight.Bold else FontWeight.Normal
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
                                val publicKeyX = listOf("0x29", "0xc2", "0xef", "0x24", "0xa4", "0xbe", "0x89", "0xfd", "0x51", "0x35", "0x89", "0x24", "0xb3", "0x2e", "0x38", "0xd2", "0x5b", "0x64", "0x9e", "0x4e", "0x96", "0xff", "0x0b", "0x6f", "0x6b", "0xe2", "0x12", "0x87", "0x1b", "0xf5", "0x26", "0x27")
                                val publicKeyY = listOf("0x9a", "0x9d", "0x6b", "0x56", "0x68", "0x29", "0xbf", "0x3a", "0xf8", "0xfe", "0xe0", "0x50", "0x94", "0x3f", "0xbb", "0x70", "0xab", "0xf5", "0xb1", "0xb3", "0x5a", "0xc1", "0xe3", "0xb8", "0x95", "0xee", "0x2e", "0xc0", "0xa8", "0x5a", "0xfb", "0xd2")
                                val hashedMessage = listOf("0x01", "0x14", "0xe3", "0x2b", "0xb0", "0x66", "0xf2", "0x7b", "0x13", "0x16", "0xbb", "0x83", "0x31", "0x6c", "0x37", "0x24", "0x9c", "0x33", "0x89", "0xe0", "0x5f", "0xfe", "0x0b", "0xc2", "0x03", "0x03", "0xdc", "0x6e", "0x9e", "0x6e", "0x0f", "0xd5")
                                val signature = listOf("0xc9", "0x77", "0x3e", "0x28", "0xaa", "0x2b", "0x6c", "0x2a", "0xe5", "0x4b", "0xf0", "0x9f", "0xaa", "0xdf", "0x64", "0xc8", "0x23", "0x99", "0xcb", "0x1a", "0xb6", "0x6e", "0xa9", "0x07", "0x24", "0x3d", "0x9b", "0x83", "0x3a", "0x9a", "0x57", "0xd2", "0x21", "0xad", "0x97", "0xb8", "0x34", "0x04", "0x03", "0x56", "0xe1", "0x4e", "0x15", "0x5c", "0x78", "0x14", "0x91", "0x7a", "0xa3", "0x76", "0x55", "0x50", "0xf9", "0x0b", "0x0c", "0x5d", "0x0b", "0x5b", "0xbe", "0x43", "0xef", "0xcc", "0x31", "0xa3")
                                val inputs = publicKeyX + publicKeyY + hashedMessage + signature

                                val onChain = true  // Use Keccak for Solidity compatibility
                                val lowMemoryMode = false

                                // First, get or use existing verification key
                                val vk = existingVk ?: run {
                                    statusMessage = "Generating verification key..."
                                    getNoirVerificationKey(circuitFile, srsFile, onChain, lowMemoryMode)
                                }
                                verificationKey = vk

                                statusMessage = "Generating proof with verification key..."
                                val startTime = System.currentTimeMillis()
                                proofBytes = generateNoirProof(
                                    circuitFile,
                                    srsFile,
                                    inputs,
                                    onChain,
                                    vk,
                                    lowMemoryMode
                                )
                                val endTime = System.currentTimeMillis()
                                val duration = endTime - startTime

                                provingTime = "Proving time: $duration ms"
                                proofResult = "Proof generated: ${proofBytes?.size ?: 0} bytes"
                                statusMessage = "Proof generation completed"
                            } catch (e: Exception) {
                                provingTime = "Proving failed"
                                proofResult = "Error: ${e.message}"
                                statusMessage = "Proof generation failed"
                                e.printStackTrace()
                            } finally {
                                isGeneratingProof = false
                            }
                        }
                    ).start()
                },
                modifier = Modifier.padding(top = 20.dp),
                enabled = !isGeneratingProof && !isVerifyingProof
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
                                            circuitFile,
                                            proof,
                                            onChain,
                                            vk,
                                            lowMemoryMode
                                        )
                                        val endTime = System.currentTimeMillis()
                                        val duration = endTime - startTime

                                        verificationTime = "Verification time: $duration ms"
                                        verificationResult = "Verification result: $result"
                                        if (result)
                                            statusMessage = "Proof verified successfully!"
                                        else
                                            statusMessage = "Proof verification failed!"
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
                        }
                    ).start()
                },
                modifier = Modifier.padding(top = 20.dp),
                enabled = !isGeneratingProof && !isVerifyingProof && proofBytes != null
            ) {
                Text(text = "Verify Proof")
            }

            Spacer(modifier = Modifier.height(40.dp))

            // Results displayed in a more organized way
            if (provingTime.isNotEmpty() || proofResult.isNotEmpty() ||
                verificationTime.isNotEmpty() || verificationResult.isNotEmpty()) {

                Text(
                    text = "Results",
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp,
                    modifier = Modifier.padding(bottom = 8.dp)
                )

                if (provingTime.isNotEmpty()) {
                    Text(
                        text = provingTime,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (proofResult.isNotEmpty()) {
                    Text(
                        text = proofResult,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (verificationTime.isNotEmpty()) {
                    Text(
                        text = verificationTime,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (verificationResult.isNotEmpty()) {
                    Text(
                        text = verificationResult,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center,
                        fontWeight = if (verificationResult.contains("true")) FontWeight.Bold else FontWeight.Normal
                    )
                }
            }
        }
    }
} 