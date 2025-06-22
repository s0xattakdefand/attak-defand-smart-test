⚔️ Concurrency / Race Testing in Smart Contracts
Concurrency (Race Condition) Testing simulates scenarios where multiple transactions or function calls interact in overlapping or conflicting ways — to detect:

❌ inconsistent state

❌ logic race gaps

❌ frontrunning vulnerabilities

❌ multi-block reentrancy

Concurrency bugs are often non-deterministic and difficult to spot in unit tests, but can be exploited for:

duplicate withdrawals

order manipulation

liquidation race wins

governance hijack

✅ Types of Concurrency / Race Testing
#	Type	Description
1	Transaction Ordering Race	Simulates tx A and tx B in different sequences (MEV, frontrunning).
2	Multi-Caller Collision Test	Two addresses interact with same state in parallel (e.g. double claims).
3	Reentrancy Race	Simulates attacker triggering logic inside a withdrawal or callback.
4	Multi-Block State Race	Conflicting state transitions across sequential blocks (e.g. unlock windows).
5	Governance Proposal Race	Competing proposals or votes interact with same target.
6	Oracle/Price Feed Race	Test decision based on changing price within tx or across blocks.
7	Upgrade Race	Simulate upgrade mid-execution or before settlement.
8	MetaTx Replay Race	Replay same meta-signed tx in different gas or block position.
9	Permit Signature Race	Permit → transferFrom race for double spend.
10	Multicall Execution Race	One subcall sets state, another overwrites or reverts in same tx.

⚔️ Concurrency / Race Attack Types
Attack	Description
Reentrancy Withdraw	Contract A calls withdraw(), attacker re-enters before balance update.
Double Claim Race	Two txs claiming same reward in rapid succession.
Governance Queue/Exec Race	Malicious proposal queued and executed before valid one.
Liquidation Race Win	Manipulate oracle just before liquidation executes.
MEV Frontrun	Exploit sequencer delay or simulate same function call before victim.
Time Window Overlap	Call function just as condition flips from valid→invalid.
Gas Brute Force	Low gas tx sets up state; high gas tx consumes it in race.
Permit→transferFrom Race	ERC20 signed permit reused across two chains or forks.

🛡️ Concurrency Defense Types
#	Defense Type	Description
1	Checks-Effects-Interactions Pattern	Prevent reentrancy by updating state before external calls.
2	ReentrancyGuard	Modifier that locks functions during execution.
3	Atomic Timestamp Locking	Require block.timestamp >= lockUntil[user] to avoid overlap.
4	Per-User Nonce Lock	Prevent repeated tx by enforcing nonce increases.
5	Double-Claim Bitmask	Use bit-based claim tracking instead of booleans or mappings.
6	Governance Hash Lock	Hash proposals with id + chainId + functionHash to avoid race.
7	Price Feed Finalization	Lock oracle values after read to ensure consistency.
8	Upgrade Staging Delay	Delay upgrade by N blocks to prevent upgrade race.
9	Batch Execution Isolation	Use internal state tracking per subcall to avoid overlap.
10	Replay Registry	Block signature reuse across parallel callers or chains.
