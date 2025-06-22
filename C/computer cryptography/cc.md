🔐 Term: Computer Cryptography — Web3 / Smart Contract Security Context
Computer Cryptography is the mathematical and computational foundation for securing data, ensuring confidentiality, authentication, and integrity. In Web3, cryptography is used to:

Authenticate users (signatures, ECDSA)

Secure transactions (hashing, Merkle trees)

Validate computations (zero-knowledge proofs)

Manage identity and access (zkLogin, MPC, ring sigs)

📘 1. Types of Computer Cryptography in Web3
Type	Description
Symmetric Cryptography	Same key for encryption and decryption (used off-chain in zk systems)
Asymmetric Cryptography	Public/private key pairs (e.g., ECDSA, BLS) for signing and key exchange
Hash-Based Cryptography	One-way functions like Keccak256, Poseidon, MiMC, Blake2b
Zero-Knowledge Proofs	Prove knowledge of a value without revealing it (zkSNARK, zkSTARK)
Merkle Trees	Used for verifiable data structures (airdrop proofs, state roots)
Multi-Party Computation	Distributed key signing or encryption with no single point of failure

💥 2. Attacks on Cryptographic Components
Attack Type	Description
Key Leakage / Replay	Reusing or leaking private keys (via phishing, frontends, bugs)
Signature Malleability	Manipulating s value to produce valid but different sigs (e.g. EIP-2)
Entropy Drift / RNG Exploit	Weak randomness leads to predictable key or value generation
Hash Collision Exploit	MD5/SHA1-style collision leads to false validation or fraud
ZK Proof Injection	Fake proof accepted if verifier is misconfigured
Poseidon Input Reveal	Improper padding or salt reuse exposes preimage in circuits

🛡️ 3. Cryptographic Defenses in Web3
Defense Strategy	Implementation in Solidity or zk-based systems
✅ Strict Signature Validation	Use ecrecover with canonical s, v checks (EIP-2, EIP-155)
✅ Hash Salt + Domain Separation	Prevent preimage attacks by adding msg.sender, domain tags
✅ ZK Verifier Constraints	Enforce unique nullifiers, constraint satisfaction in circuits
✅ Merkle Root Pinning	Only accept known-good roots in a Merkle/MiMC proof system
✅ Reentrancy + Timestamp Guard	Avoid repeated key usage in flash/multi-block attacks
✅ MPC / Hardware Wallet Usage	Keep keys off-chain, use distributed signature schemes

✅ 4. Solidity Code: CryptoVerifier.sol
This contract:

Validates signatures

Verifies Poseidon hashes (via external verifier)

Prevents signature replay

Enforces hash domain separation