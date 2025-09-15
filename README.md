# Anastasia: Cinderella's Stepsister Turning Shabby X.509 Certificates into Elegant Anonymous Device Attestations with the Magic of Noir

Built during [ETHTokyo 2025 Hackathon](https://taikai.network/en/ethtokyo/hackathons/hackathon-2025)

## Project description

Anastasia is a zero-knowledge system that proves the validity of X.509 certificate chains while revealing only the minimum information required.  
Inspired by the prior work *Cinderella* (IEEE S&P 2016), which transformed X.509 certificates into anonymous credentials with zk-SNARKs, Anastasia extends the idea to make it practical on mobile devices, specifically Android **Key Attestation**.

**Key contributions:**
- Replaces Pinocchio (Linear PCP) with **UltraHonk** (Plonk-style proving system), enabling efficient prover on smartphones.
- Circuits written in **Noir DSL**, making them maintainable and extensible.
- Adds **ECDSA signature verification**, supporting Android’s native attestation certificates.
- Adopts a **split-proof approach**: instead of verifying an entire chain at once, each certificate is proved separately and linked via commitments, reducing memory and CPU load on mobile devices.
- Leverages Cinderella’s insight: *parse outside the circuit, re-serialize inside*. Thanks to the bijective property of ASN.1 DER encoding, we can prove correctness without costly parsing inside the circuit.

With Anastasia, we demonstrate that a smartphone can produce a zero-knowledge proof that its attested key truly originates from a Secure Element, without leaking identifiers that would enable tracking.

## Technologies used

- **Noir** (circuit DSL)
- **UltraHonk / Plonk-style proving**
- **Rust** (ZK library, bindings)
- **Mopro** (bridging Noir/Rust to Kotlin)
- **Kotlin** (Android SDK + demo app)
- **Solidity** (Verifier smart contract)
- **ASN.1 DER / X.509** (certificate)

## Basic architecture

**Prover (Android)**
- Generates attestation chain (Secure Element)  
- Parses X.509 certs in Rust, re-serializes inside Noir circuit  
- Produces ZK proof (split per certificate)  

**Verifier (Smart Contract)**
- Solidity contract (generated via Noir standard toolchain)  
- Verifies ZK proof of certificate validity  

## Deployment

- Solidity verifier contract deployed on testnet

### Android

Follow these steps to build and run this Android app locally:

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd <cloned_directory>/android/v2
    ```

2.  **Open the project in Android Studio:**
    *   Launch Android Studio.
    *   Select "Open an existing Android Studio project" and specify the `android/v2` folder within the cloned directory.

3.  **Set up the API Key (Environment Variable):**
    *   This project requires an Infura API key to communicate with the Sepolia testnet. The API key is read from an environment variable named `SEPOLIA_API_KEY` during the build.
    *   **Set the `SEPOLIA_API_KEY` environment variable beforehand, according to your operating system and terminal environment.**
        *   Example (for bash/zsh on Linux/macOS):
          ```bash
          export SEPOLIA_API_KEY="<your_infura_sepolia_api_key>"
          ```
        *   If building directly from Android Studio, you can also set the environment variable in the IDE's run configuration:
            1.  From the menu bar, select `Run` > `Edit Configurations...`.
            2.  In the left pane, select the `app` configuration.
            3.  Add `SEPOLIA_API_KEY=<your_infura_sepolia_api_key>` to the "Environment variables" field.
    *   **Note:** Manage your API key securely. Be careful not to commit it directly to the repository.

4.  **Build and Run:**
    *   Wait for Android Studio to complete the project sync. (After setting the environment variable, a Gradle sync may be required. Press the elephant icon button in the toolbar.)
    *   Select a connected physical device or an Android Emulator.
    *   From the menu bar, select `Run` > `Run 'app'` or click the green play button in the toolbar.

This will build the app and run it on the selected device/emulator.
