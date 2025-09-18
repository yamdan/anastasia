# Anastasia Circuits Overview

![circuits.png](./circuits.png)

For proving the knowledge of certificates used in **Android Key Attestation**, we define a series of four circuits corresponding to each step in the certificate chain.  
All circuits share a common structure of inputs and proving statements, with differences only in the signature algorithm and the content of commitments.

## Common Structure

### Public inputs
- `now`: UTC datetime when the proof is generated, encoded as seven bytes (year1, year2, month, day, hour, minute, second)
- `prev_cmt`: commitment of the issuer’s distinguished name, public key, and key identifier (`c[i-1]` in the figure)
- `next_cmt`: commitment of the subject’s distinguished name, public key, and key identifier (`c[i]` in the figure)

### Private inputs
- Parsed certificate elements: serial number, issuer/subject names, validity, subject public key, key identifiers, extensions, signature value  
- Issuer’s public key  
- Randomness used for commitments (`prev_cmt_r`, `next_cmt_r`)  

### Proving statements
- `reSerializedCert` is reconstructed DER of tbsCertificate from the parsed certificate elements  
- `hash` = Hash(`reSerializedCert`) with the algorithm of the circuit  
- Signature verification of `hash` with issuer public key succeeds  
- `now` lies within validity period  
- `prev_cmt` and `next_cmt` match commitments with the given randomness  
## Circuits

### (1) **RSA-SHA256-CA** (*not implemented yet*)  
- Proves the certificate issued by **Google Root CA → Droid CA2**  
- Signature algorithm: **sha256WithRSAEncryption**  
- `prev_cmt`: root CA (issuer info) → `c0`  
- `next_cmt`: Droid CA2 (subject info) → `c1`  

### (2) **ES384-CA** (*not implemented yet*)  
- Proves the certificate issued by **Droid CA2 → Droid CA3**  
- Signature algorithm: **ecdsa-with-SHA384**  
- `prev_cmt`: Droid CA2 (issuer info) → `c1`  
- `next_cmt`: Droid CA3 (subject info) → `c2`  

### (3) **ES256-CA**  
- Proves the certificate issued by **Droid CA3 → StrongBox Internal CA**  
- Signature algorithm: **ecdsa-with-SHA256**  
- `prev_cmt`: Droid CA3 (issuer info) → `c2`  
- `next_cmt`: StrongBox CA (subject info) → `c3`  

### (4) **ES256-EE** (*currently implemented without pseudonyms*)  
- Proves the end-entity certificate issued by **StrongBox Internal CA → Android Keystore Key**  
- Signature algorithm: **ecdsa-with-SHA256**  
- `prev_cmt`: StrongBox CA (issuer info) → `c3`  
- Adds pseudonym generation (*not yet implemented*):
  - `ctx`: context information
  - `nym`: pseudonym = f(subject public key, `ctx`, `userSecret`)  
  - `userSecret`: private randomness to blind subject public key  

## Verification Flow

As shown in the bottom part of the figure, the verifier receives the following **public inputs**:

- Root CA certificate information:
  - subject
  - subject public key
  - subject public key identifier
- `now`: current UTC datetime  
- Chain commitments: `c1`, `c2`, `c3`  
- `ctx`: context information for pseudonym generation  
- `nym`: context-specific pseudonym  

With these inputs, the verifier runs zero-knowledge verification of the four proofs in sequence:

1. Verify the proof for the Root CA → Droid CA2 (`RSA-SHA256-CA`)  
2. Verify the proof for Droid CA2 → Droid CA3 (`ES384-CA`)  
3. Verify the proof for Droid CA3 → StrongBox CA (`ES256-CA`)  
4. Verify the proof for StrongBox CA → End-Entity Key (`ES256-EE`)  

If all proofs are valid, the verifier is convinced that the end-entity certificate (Android Keystore Key) is correctly chained to the Google Root CA, without learning any private certificate contents.  
In particular, the verifier checks that the pseudonym `nym` corresponds to the subject public key at the end of the chain.  
This ensures that `nym` can be safely used as a context-specific pseudonym of a device-attested public key.

## Current Limitations
- Only 2 certs supported (full chain = 5 certs)  
- Proof generation: >20s on Google Pixel 9a  
- Solidity verifier gas-heavy  
- No revocation (CRL/OCSP)  
- No formal security audit yet  
