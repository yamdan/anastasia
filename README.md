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

- Android demo app (APK to be published on GitHub Repo)
- Solidity verifier contract deployed on testnet
