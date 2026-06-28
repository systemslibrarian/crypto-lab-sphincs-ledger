# crypto-lab-sphincs-ledger

## What It Is

This project is a browser demo of SLH-DSA (SPHINCS+), with supporting SHA-256 Merkle tree and WOTS+ visualizations that make the signing flow easier to inspect. SLH-DSA solves the digital-signature problem: a signer produces a public verifiable proof that a message came from the holder of the private key and was not modified. The scheme is an asymmetric, hash-based, post-quantum signature system standardized in NIST FIPS 205. In this demo, the security story is presented honestly: the production signing path is SLH-DSA, while the Merkle tree and WOTS+ tabs are educational views of the primitives beneath it.

## When to Use It

- Use it for long-lived software releases or archive signatures when conservative post-quantum assurances matter more than compact signatures.
- Use it for offline or low-frequency signing workflows because SLH-DSA trades very large signatures for a hash-only security foundation.
- Use it for teaching or internal reviews when you need to show how SHA-256 Merkle trees, WOTS+, and SLH-DSA fit together in one place.
- Do not use it for bandwidth-sensitive or latency-sensitive protocols because the signature sizes in the implemented parameter sets are much larger than RSA, Ed25519, or ML-DSA.
- Do not use it as a production signing implementation — it is a teaching demo for SLH-DSA and its underlying primitives, not an audited library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-sphincs-ledger](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/)**

The demo lets you generate keys, sign messages, verify signatures, inspect a SHA-256 Merkle tree authentication path, experiment with a WOTS+ chain reveal, and append signed entries to a browser-side ledger. The main controls are the Parameter set selector, Message to sign textarea, Number of leaves selector, Message nibble input, and Chain index input.

## What Can Go Wrong

- **Very large signatures** — SLH-DSA signatures are far larger than RSA, Ed25519, or ML-DSA; dropping them into bandwidth- or latency-sensitive protocols can break those protocols.
- **Slow signing** — the conservative hash-based construction makes signature generation comparatively expensive, a poor fit for high-throughput signing.
- **Parameter-set tradeoffs** — the "fast" vs "small" SLH-DSA variants trade signature size against speed; choosing the wrong profile for the workload hurts either bandwidth or latency.
- **Security rests entirely on the hash function** — SLH-DSA has no number-theoretic fallback, so the approved SHA-2/SHAKE parameter sets must be used exactly as standardized.
- **Misreading the educational tabs** — the Merkle-tree and WOTS+ views are simplified pedagogical primitives, not the full SLH-DSA hypertree; only the SLH-DSA path is the real signing scheme.

## Real-World Usage

- **Long-lived software and firmware signing** — conservative post-quantum assurance for artifacts that must remain verifiable for decades.
- **NIST FIPS 205** — SLH-DSA is the standardized stateless hash-based signature, recommended where a non-lattice PQ signature is wanted as a hedge.
- **Code, release, and archive signing** — offline, low-frequency signing where large signatures are acceptable in exchange for hash-only security.
- **Root-of-trust and PKI hedges** — hash-based signatures back trust anchors that are hard to rotate and need quantum-resistant longevity.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-sphincs-ledger
cd crypto-lab-sphincs-ledger/demos/sphincs-ledger
npm install
npm run dev
```

## Related Demos

- [crypto-lab-lms-ledger](https://systemslibrarian.github.io/crypto-lab-lms-ledger/) — LMS/HSS with W-OTS+, the stateful hash-based signature family (NIST SP 800-208).
- [crypto-lab-lms-xmss](https://systemslibrarian.github.io/crypto-lab-lms-xmss/) — LMS and LM-OTS internals, contrasting stateful trees with SLH-DSA's stateless design.
- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — ML-DSA (FIPS 204), the lattice PQ signature with far smaller signatures.
- [crypto-lab-falcon-seal](https://systemslibrarian.github.io/crypto-lab-falcon-seal/) — Falcon (FN-DSA), the compact NTRU-lattice PQ signature.
- [crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — SHA-256 Merkle trees and inclusion proofs, the structure underpinning hash-based signatures.

## Project Layout

The demo source lives under `demos/sphincs-ledger/` in the repository, so after
cloning, run the dev server from that subdirectory:

```bash
cd crypto-lab-sphincs-ledger/demos/sphincs-ledger
npm install
npm run dev
```

No environment variables are required.

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
