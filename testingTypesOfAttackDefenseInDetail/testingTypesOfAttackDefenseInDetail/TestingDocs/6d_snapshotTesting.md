🧾 Snapshot Testing in Smart Contracts
Snapshot Testing captures the state of a smart contract at a given point, executes some actions, and then compares the post-state to expected values — or restores it to verify that logic behaves reversibly, consistently, and safely.

Snapshot testing is powerful for:

🔁 Time travel in fuzz and integration tests

✅ Validating idempotent logic (same inputs = same outputs)

🧪 Ensuring no unexpected mutations after a batch, upgrade, or strategy call

🔄 Testing rollback in forks, DAOs, multicalls

✅ Types of Snapshot Testing
#	Type	Description
1	State Snapshot + Restore	Save state → run tx → restore → re-run or compare.
2	View-Only Snapshot Comparison	Read state → run logic → compare final state without revert.
3	Fuzz Snapshot Replay	Run fuzzed sequence, then replay it after snapshot restore.
4	Upgrade Snapshot Comparison	Snapshot before & after upgrade to verify state drift.
5	Cross-Chain Snapshot Alignment	Match L1↔L2 contract state for sync integrity.
6	Forked Snapshot Isolation	Run full test inside a fork snapshot to prevent real mutation.
7	Proposal Snapshot Testing	Take snapshot before DAO vote → simulate execution → compare results.
8	Balance Snapshot	Record ETH/ERC20 balances before and after sensitive calls.
9	Selector Snapshot	Track active selectors in fallback routers before & after fuzz.
10	Storage Slot Snapshot	Direct slot-by-slot tracking using vm.load().

⚔️ Bugs Caught by Snapshot Testing
Type	Vulnerability
Unexpected State Drift	Function modifies storage unintentionally
Access Escalation	Role changes over time without authorized input
Reentrancy Effect	State looks correct during execution, but not after
Upgrade Mutation	Upgrade wipes or reshuffles storage
Multicall Side Effects	Later subcall modifies something the first call relies on
Gas Bombs	Storage expansion that wasn’t obvious in per-function tests

🛡️ Snapshot Best Practices (Foundry / Hardhat)
Tool	Action
vm.snapshot()	Save current EVM state (Foundry)
vm.revert(id)	Restore to previous snapshot
vm.load(addr, slot)	Read raw storage to diff states
vm.record() / vm.accesses()	Track what was written and read
Forks	Use snapshots inside forked chains (createSelectFork)
balanceBefore / balanceAfter	Track native/ERC20 balance snapshots