🌪️ Entropy Drift Testing in Smart Contracts
Entropy Drift Testing evaluates how your contract behaves under changing randomness, hash values, calldata, or selector entropy — ensuring that its security, determinism, and logic flow remain intact when faced with unpredictable or mutated input.

Entropy drift is especially dangerous in:

🧠 ZK/metaTx payloads

🕵️ Off-chain signatures

🔀 Function selectors

🔑 Commit-reveal schemes

📦 Proxy fallback + calldata routing

✅ Types of Entropy Drift Testing
#	Type	Description
1	Selector Entropy Drift	Mutate msg.sig to check if unknown selectors unlock logic.
2	Hash Input Drift Test	Vary inputs to keccak256, Poseidon, or Groth16 and validate output binding.
3	Commit-Reveal Drift Test	Drift commit input and replay to detect reuse or bypass.
4	Nonce / Salt Drift Test	Simulate changes in nonces, salts, or unique IDs and test storage drift.
5	ZK Payload Drift	Alter proof hash, input fields, or witness data and verify rejection.
6	Randomized Access Drift	Alter randomness-dependent behavior (e.g., lottery winners).
7	Signature Entropy Drift	Mutate v, r, s, or domain input and test replay or impersonation.
8	Fallback Selector Drift	Send slightly-altered function selectors to see if fallback unlocks hidden paths.
9	Cross-Chain Entropy Mismatch	Compare entropy handling across chains or forks.
10	Time-based Entropy Drift	Drift block.timestamp, block.number, and test logic resistance.

⚔️ Attack Types Detected by Entropy Drift Testing
Attack Type	Description
Selector Collision Attack	Mutated selector reactivates legacy function via fallback.
Hash Replay Drift	Commit value reused under slightly altered inputs.
Signature Drift Attack	Reuse signature with different calldata or chain.
Randomness Exploit	Predicted or manipulated randomness to gain unfair advantage.
ZK Replay Drift	Valid zkProof used for different payload or identity.
Calldata Entropy Abuse	Injected entropy into ABI-encoded values triggers logic bugs.
Upgrade Drift	Upgrade logic behaves differently due to hash/selector mismatch.

🛡️ Defense Types Against Entropy Drift
Defense Type	Description
✅ Strict Selector Registry	Enforce exact selector list for fallback routing.
✅ Hash Binding with Context	Include msg.sender, chainId, and contract address in all hash ops.
✅ Non-Replayable Commitments	Tie commitments to nonce, block, or role.
✅ EIP-712 Domain Separation	Prevent drift in signature by enforcing strict structure.
✅ ZK Nullifier Registry	One-time usage log of zk proof nullifiers.
✅ Bounded Randomness Usage	Use VRF or capped random ranges to avoid entropy overflow.
✅ Gas-Capped Fallback	Prevent large mutated inputs from becoming DoS vector.
✅ Signature Entropy Normalization	Validate v, s values and reject low entropy inputs.
