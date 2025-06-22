🔁 Replay Testing in Smart Contracts
Replay Testing simulates the re-execution of previously recorded transactions, payloads, or sequences to validate:

✅ Determinism

✅ Reentrancy resilience

✅ Signature reuse protection

✅ State transition integrity over time

In smart contracts, replay testing is critical for uncovering:

Zero-Day regressions

Signature forgery attacks

Cross-chain inconsistencies

Governance replays

MetaTx or DAO replay vulnerabilities

✅ Types of Replay Testing
#	Type	Description
1	Tx Replay Testing	Replay full transaction calldata to detect idempotency or drift.
2	Signature Replay Testing	Reuse ECDSA signatures to check for MetaTx/Permit abuse.
3	State Drift Replay	Replay an old sequence and compare pre/post state hash.
4	Multicall Replay	Re-run multicall payloads to detect sequence-dependent failures.
5	Time-Skewed Replay	Run same calldata at different timestamps to check invariants.
6	Governance Replay	Replay previously executed proposals to check if they can be double-triggered.
7	Cross-Chain Message Replay	Reuse same payload in another domain to test message protection (e.g., bridge re-entry).
8	Permit Replay	Reuse ERC20/721 permits or signatures past expiration or nonce.
9	Fallback Replay	Replay malformed or mutated selectors that trigger fallback logic.
10	Upgrade Replay	Re-trigger upgrade payloads to detect unintended storage mutations or logic divergence.

⚔️ Replay Attack Scenarios
Type	Example
Signature Replay	MetaTx from SafeTx signed once, used again by attacker
Governance Replay	Proposal X executed again via queue + execute
Cross-Chain Replay	Layer 2 withdrawal relayed multiple times on L1
Time-Shift Replay	Proposal executed before valid time window
Fallback Replay	0xdeadbeef called again via delegatecall to trigger hidden logic

🛡️ Defense Mechanisms
Defense Type	Implementation
Signature Nonces	Enforce unique per-signer nonces (permit, metaTx)
Replay Registry	Store hashes of executed payloads
Time Locks	Prevent re-execution within the same block/period
Hash Verification	Hash-based execute(bytes32 hash, bytes calldata data) calls
Cross-Domain Guards	Check origin chain/message sender in bridge or L2
Fallback Selectors Lock	Reject repeated unknown selectors via registry