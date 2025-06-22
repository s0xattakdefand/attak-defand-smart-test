📡 Term: Compromising Emanations — Web3 / Smart Contract Security Context
Compromising Emanations (also known as TEMPEST attacks in traditional infosec) refer to unintended information leakage via physical or side-channel emissions, such as radio frequency, power usage, timing, or memory access patterns.

In Web3, compromising emanations manifest as information leakage through observable signals in smart contracts or associated systems — such as:

Gas usage

Call stack depth

Opcode sequences

ZK proof lengths

Oracle calldata patterns

📘 1. Types of Compromising Emanations in Web3
Type	Description
Gas-Based Emanation	Leak sensitive data through different gas costs (e.g., if/else branch)
Opcode Signature Emanation	Unique opcode sequences expose logic paths
ZK-Proof Length/Shape	Varying zkSNARK output length or structure leaks internal values
Oracle Calldata Patterns	Data size, timing, or feed inclusion reveals what’s being updated
Contract Call Tree Drift	Multi-call execution path leaks user roles or decisions
Cross-Chain Event Order	Message order leaks priority or trigger source

💥 2. Attacks Leveraging Compromising Emanations
Attack Type	Description
Gas Oracle Attack	Infer which branch executed by comparing gas used
Opcode Profiling Attack	Replay attacker contract to detect target logic execution pattern
ZK Emanation Timing	Proof generation time/size reveals hidden input structure
MEV Transaction Leak	Observe compressed calldata hints to profitable position
Merkle Depth Correlation	Proof depth leaks position in allowlist, airdrop, or NFT rarity

🛡️ 3. Defenses Against Compromising Emanations
Defense Strategy	Implementation
✅ Constant-Gas Branching	Ensure all branches consume equal gas (e.g., dummy writes)
✅ Opcode Obfuscation/Normalization	Use standardized opcode paths, avoid functionally unique patterns
✅ Fixed-Size Proofs & Payloads	Pad all proofs/calldata to uniform length
✅ Randomized Execution Noise	Add dummy calls, salt, or delays to break inference
✅ Merkle Path Equalizer	Use balanced trees or randomized ordering to obscure proof paths

✅ 4. Complete Solidity Code: EmanationSafeContract.sol
This contract:

Executes dummy logic to prevent gas-based branching inference

Pads output values

Protects state and logic from timing or opcode-based leak analysis