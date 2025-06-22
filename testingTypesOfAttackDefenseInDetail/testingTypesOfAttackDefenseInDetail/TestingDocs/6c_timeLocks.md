⏱️ Timelocks in Smart Contracts
A Timelock is a smart contract mechanism that delays execution of sensitive actions (e.g., upgrades, transfers, governance votes) for a specified period, giving time for review, cancellation, or community reaction.

Timelocks are a core defense in DAOs, treasuries, and upgradeable contracts — but they also introduce attack surfaces if misconfigured.

✅ Types of Timelocks
#	Type	Description
1	Simple Delay Timelock	Execution of a queued transaction is only allowed after a time delay (e.g., 2 days).
2	Role-Gated Timelock	Only specific roles (e.g., admin, proposer) can queue, cancel, or execute actions.
3	Batch Timelock	Multiple actions are queued and executed together after the delay.
4	Upgrade Timelock	Delays execution of proxy upgrades or new implementations.
5	Governance Timelock	Proposals from DAOs must wait a delay before execution (e.g., Compound, Aave).
6	Nested Timelock	A timelock contract owns another timelock or proxy, creating chained delays.
7	One-Time Timelock	Delay is applied only once per operation or function, often used for vesting or launches.
8	Recurring/Interval Timelock	Execution only allowed every N blocks or time units (e.g., emissions every 1 week).
9	Hash-Based Timelock (Commit-Reveal)	Commit a hash now, reveal data later after a delay — often used in auctions or oracles.
10	Entropy-Tied Timelock	Delay enforced via entropy (block.timestamp, VRF proof) rather than static duration.

⚔️ Attack Vectors on Timelocks
#	Attack	Description
1	Race-to-Queue	Malicious tx queued before legitimate one with same target/data — front-run.
2	Delay Reduction Exploit	Admin reduces delay to 0 or low value before queuing & executing instantly.
3	Timelock Ownership Leak	If timelock is owned by another contract (e.g., proxy), logic may bypass delay.
4	Commit-Reveal Replay	Replay a committed hash for different action — same commit, multiple reveals.
5	Cancel Gap Abuse	Timelock tx is not cancelable fast enough before it executes — no veto time.
6	Fallback Injection via Timelock	Timelock executes arbitrary call() to fallback functions, enabling backdoors.
7	Entropy Drift Skip	If entropy used (e.g., VRF), attacker predicts or manipulates delay expiry window.

🛡️ Defensive Best Practices
Type	Defense
Admin Delay Enforcer	Prevent changing minDelay without going through another timelock.
Selector Registry	Limit function selectors that can be called via execute() in timelock.
Timelock Ownership Guard	Don't let arbitrary contracts own timelocks — avoid circular ownership.
Delay Boundaries	Set reasonable minDelay, maxDelay, and validate delay input.
Event + Hash Tracking	Log and verify queued txs to detect unauthorized inserts.
Commit-Reveal Nonce	Tie each hash to a unique nonce or sender to prevent replay.