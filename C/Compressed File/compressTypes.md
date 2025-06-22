🗜️ Term: Compressed File — Web3 / Smart Contract Security Context
A Compressed File refers to data that’s been reduced in size using encoding algorithms (e.g., gzip, zstd, Brotli), often to optimize storage, bandwidth, or execution efficiency. In Web3, compressed files (or compressed calldata) are vital due to gas limitations, on-chain storage costs, and off-chain-to-on-chain bridging.

📘 1. Types of Compressed Files in Web3
Type	Description
Off-chain File Compression	IPFS, Arweave, or server-hosted compressed JSONs, used in NFTs or metadata
On-chain Calldata Compression	Smart contract input reduced using custom encoding (e.g., RLE, bitmap)
Zero-Knowledge Compression	ZK circuits reduce state to small proof blobs (zkSNARK/zkSTARK)
Merkle-Compressed Data	Use Merkle trees to reduce large datasets to a root
L2 Blob Compression (EIP-4844)	Store compressed data as blobs for cheaper storage

💥 2. Attacks on Compressed Files
Attack Type	Description
Decompression Bomb	Malicious file decompresses to extreme size → gas exhaustion or DoS
Malformed Compression Format	Broken format causes runtime failure in decompressor logic
Phantom Data Injection	Data hidden in compressed file to mislead parsing or validation
ZK Proof Poisoning	Compressed proof blob claims false validity, attacker bypasses verification
Replay of Compressed Payloads	Reuse compressed calldata to replay critical transactions

🛡️ 3. Defenses for Compressed File Use
Defense Strategy	Web3 Implementation
✅ Gas-bound decompression	Reject input if decompressed size exceeds safety threshold
✅ Format validation	Ensure compressed data conforms to expected schema or structure
✅ Proof + root commitment	Hash of uncompressed form must match pre-committed root/hash
✅ ZK attestation of integrity	Require ZK proof that data decompresses to valid structure
✅ Nonce/checkpoint gating	Prevent replay of identical compressed calldata

✅ 4. Complete Solidity Code: CompressedDataHandler.sol
This contract demonstrates:

Receiving compressed calldata

Validating its size and structure

Simulating decompression

Root-checking the uncompressed version

