🔑 Term: Connection Signature Resolving Key — Web3 / Smart Contract Security Context
A Connection Signature Resolving Key (CSRK) refers to the public key, hash, or key commitment used to verify the authenticity of a cryptographic signature that originates from a peer-to-peer, bridge, relay, or off-chain system connection.

In Web3, it acts as a trust anchor to validate connection attempts, signed payloads, or bridge messages, ensuring that:

Only trusted entities can initiate or authorize cross-domain messages

Signatures can be verified using resolvable or registered keys

Connections (e.g., between oracles, bridges, relays, wallets) are secure

📘 1. Types of CSRK Usage in Web3
Usage Type	Description
Bridge Relay Verification	Relayer sends signed payload; CSRK verifies signer authenticity
Off-Chain Oracle Signature	Off-chain oracle signs data; CSRK verifies signature via on-chain key
MetaTx Gateway Auth	Gasless transactions signed off-chain; CSRK validates signature origin
zkRelay Commitment	Connection key embedded in ZK proof circuit or nullifier tree
Cross-Chain Wallet Sync	Wallet signs session info or auth tokens with CSRK

💥 2. Attack Vectors Without Secure CSRK Usage
Attack Type	Description
Signature Spoofing	Malicious actor forges payload; no CSRK to check signer
Relay Injection Attack	Untrusted relayer pushes forged messages to bridge
Session Hijacking	Wallet’s key not resolved correctly → spoofed connection
ZK Proof Verification Drift	Wrong key used in ZK circuit causes fake proof acceptance
Expired or Replaced Key Replay	Old keys reused without expiry or revocation check

🛡️ 3. Defense Strategies for Secure CSRK Validation
Strategy	Solidity or Protocol Pattern
✅ Public Key Registry	Use SignatureKeyRegistry.sol to store valid CSRKs
✅ Replay Guard / Nonce Checks	Require nonce or session ID in signed payload
✅ Hash Commitments or KDF	Derive resolving key via precommitted entropy / identity
✅ Timestamp-Scoped Keys	CSRKs rotate per epoch or block window
✅ ZK Key Inclusion	CSRK verified inside circuit or via nullifier binding

✅ 4. Solidity Code: SignatureKeyRegistry.sol
This contract:

Registers and manages valid CSRKs

Verifies ECDSA signatures using stored keys

Logs connection signature events