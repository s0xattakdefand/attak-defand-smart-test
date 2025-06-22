🕵️ Term: Compression Ratio Info-leak Made Easy (CRIME) — Web3 / Smart Contract Security Context
CRIME is a real-world cryptographic side-channel attack that exploits the relationship between compression and encryption to leak secret data. In traditional web contexts, CRIME targeted TLS+gzip. In Web3, this translates to:

An attack where an adversary infers private or sensitive on-chain/off-chain data by manipulating compressed payloads, observing gas usage, calldata length, entropy drift, or oracle proof size.

📘 1. Types of CRIME in Web3
Type	Description
Gas-Based Compression Leakage	Attack leverages how calldata size affects gas (cheaper when compressible)
ZK-Proof Compression Drift	Compressed proof size reveals information about hidden inputs
Merkle Payload Correlation	Small Merkle proof sizes leak inclusion position or structure
On-Chain Calldata Feedback	Use repeated compressed submissions and compare success/gas vs failure
Oracle Feed Size Leakage	Compressed feed updates leak which tokens or values are changing

💥 2. Attacks Using CRIME Techniques
Attack Vector	Explanation
Adaptive Compression Guessing	Attacker injects guesses into calldata; observes gas or size drift
Entropy Drift Analysis	Compares zkSNARK proof length to infer sensitive inputs
Gas Timing Oracle	Measures difference in gas costs across compressed calldata variants
Compression+Encryption Correlation	If encrypted data is compressed before, size reflects structure (e.g., ZK login)
Bridge Proof Discriminator	Compressed L2 proof leaks which branch of logic was executed

🛡️ 3. Defenses Against CRIME in Web3
Defense Strategy	Implementation
✅ Disable compression pre-ZK	Never compress user-controlled content before hashing/proving
✅ Pad compressed payloads	Fixed-length ZK proofs, calldata, or relay messages
✅ Entropy bounding	Reject input with extremely low/high entropy or compressibility
✅ ZK-verified zero-leak proofs	Only accept proofs from circuits that mask all structural outputs
✅ SimStrategyAI fuzz coverage	Fuzz contract under variable calldata to detect info leakage

✅ 4. Solidity Code: CrimeSafeCompressedRouter.sol
This contract:

Accepts compressed payloads

Rejects if size-to-entropy ratio is abnormal (simulating CRIME defense)

Emits analysis logs for audit or telemetry