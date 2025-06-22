⚔️ Term: Conflict Resolution — Web3 / Smart Contract Security Context
Conflict Resolution refers to the process of detecting, managing, and resolving competing or contradictory states, actions, or updates within decentralized systems. In Web3, conflict resolution mechanisms are critical for:

Handling governance proposal collisions

Managing multi-role execution disputes

Resolving cross-chain or cross-shard state disagreements

Mitigating replay, fork, or timing conflicts in smart contract logic

Proper conflict resolution ensures protocol consistency, fair governance, and secure execution even in adversarial or asynchronous environments.

📘 1. Types of Conflict Scenarios in Web3
Conflict Type	Description
Governance Proposal Conflict	Two or more active proposals target the same contract state
Role Execution Conflict	Multiple privileged roles attempt to execute contradictory actions
Cross-Domain State Conflict	L1 and L2 (or zkBridge) disagree on message state or result
Replay/Fork Conflict	Same payload or message appears valid in two different epochs or forks
Timing Conflict (Race Condition)	Multiple transactions compete to update critical state

💥 2. Attack Vectors from Unresolved Conflicts
Attack Scenario	Description
Proposal Front-Run	Malicious proposal is queued and executed before a valid one
Multi-Signer Dispute	Two signers send contradicting instructions → fork or loss of consensus
Bridge Relay Replay	Message is replayed due to domain disagreement
DAO Double-Spend Conflict	Two DAO votes try to spend same funds in parallel
Race-Based Slashing Conflict	Competing slashes applied to same validator

🛡️ 3. Conflict Resolution Mechanisms
Mechanism	Solidity or Protocol Strategy
✅ Proposal Queue & Priority	Queue proposals by target + timestamp, reject duplicates
✅ Hash-Based Determinism	Only apply config if hash(state) matches expected snapshot
✅ Nonce or Epoch Locks	Prevent multiple updates within same block/epoch for same CI
✅ Voting Conflict Arbitration	CCB or dispute resolver contract picks outcome based on stake/quorum
✅ Fork-Consistency Anchors	Track finality of state across chains to prevent replay

✅ 4. Solidity Code: ConflictResolutionCenter.sol
This contract:

Registers actions that could conflict

Detects collisions

Applies resolution logic via timestamps, roles, or quorum