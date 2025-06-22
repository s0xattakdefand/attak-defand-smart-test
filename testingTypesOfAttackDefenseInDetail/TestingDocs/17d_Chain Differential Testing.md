✅ Types of Chain Differential Testing
#	Type	Description
1	State Differential Testing	Compares final state (e.g., balances, flags) after same input on two chains.
2	Event Differential Testing	Ensures events emitted are identical in structure and data across chains.
3	Gas Differential Testing	Measures and compares gas consumption drift between chains.
4	Selector Differential Testing	Tracks how the same msg.sig behaves (fallbacks, routers, proxies).
5	Proxy Layout Differential	Detects storage drift post-upgrade between L1 and L2 proxy instances.
6	Oracle Value Drift Testing	Compares off-chain data delivered to different chains.
7	Bridge Replay Drift	Replay a message across chains and observe divergences.
8	Governance Differential	Execute same DAO proposal across domains, validate votes/results match.
9	Block Timestamp Drift	Simulate timed function calls and compare how block delays affect behavior.
10	Multicall Behavior Drift	Batch execution on both chains; compare subcall order and result symmetry.

⚔️ Attack Types Detected by Chain Differential Testing
#	Attack Type	Description
1	Cross-Chain Replay Attack	Replay same message or tx on another chain to duplicate effects.
2	Oracle Drift Exploit	Exploit timing/price difference between chains to extract arbitrage.
3	Selector Drift Exploit	Same selector maps to different logic due to compiler/proxy drift.
4	Proxy Storage Collision	Storage layout mismatch causes state overwrite on one chain.
5	Governance Desync	Proposal accepted on one chain, rejected on another — triggers execution drift.
6	Permit Replay	Use same permit() signature on L1 and L2, bypassing auth logic.
7	Gas Reentrancy Abuse	L2 chain allows more reentry gas, enabling reentrancy only there.
8	Fallback Exploit Drift	Fallback function reachable on one chain but not another.
9	Upgrade Injection on L2	Logic upgraded only on L2, but looks same in ABI, masking backdoor.
10	Entropy Fork Exploit	Message signed for one chain reused on another with altered entropy.

🛡️ Defense Types Against Chain Differential Bugs
#	Defense Type	Description
1	Cross-Chain Nonce Registry	Prevents replay by tracking executed payloads per chain.
2	Upgrade Symmetry Checker	Ensures all chain deployments are upgraded with same bytecode + layout.
3	Storage Slot Validator	Verifies proxy slot mappings are identical post-deploy.
4	Domain-Aware Signature Binding	Bind all off-chain signatures to specific chainId.
5	Cross-Chain Oracle Synchronizer	Enforce strict time/value sync between oracles.
6	Replay ReplayGuard	Prevents bridge or governance replay across chains.
7	Selector Consistency Checker	Tracks fallback/selectors to ensure uniform logic mapping.
8	Multicall Result Validator	Compares subcall outcomes and gas usage across domains.
9	Governance Lockstep Enforcement	Enforce same execution path for proposals via hash binding.
10	Fork Testing + State Snapshot	Replay and snapshot both forks before and after to catch divergence.
