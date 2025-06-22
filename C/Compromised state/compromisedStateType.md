🧨 Term: Compromised State — Web3 / Smart Contract Security Context
A Compromised State in Web3 refers to a condition where a smart contract’s internal state, such as storage variables, roles, balances, or access structures, has been maliciously altered, either directly by an attacker or indirectly through a logic flaw or vulnerability.

In short: the contract still runs, but its internal data no longer reflects a valid or secure state — creating hidden or persistent vulnerabilities.

📘 1. Types of Compromised State
Type	Description
Storage Variable Tampering	Attacker corrupts mappings, counters, or roles directly
Unintended Role Reassignment	Logic flaw or backdoor grants elevated roles to wrong address
Nonce or Counter Drift	Replays or double-submits desync internal counters
Proxy Storage Collision	Logic upgrade alters storage layout, corrupting contract state
Orphaned Modules / Plugins	DAO upgrades or disables modules without cleaning up state
Cross-Contract Drift	One contract's state is updated, but dependent contracts remain stale

💥 2. Attacks That Cause Compromised State
Attack Technique	Description
Uninitialized Proxy Exploit	Attacker calls initialize() on unprotected proxy
Delegatecall Hijack	Malicious contract writes into target's storage
Storage Layout Drift Attack	Logic contract change breaks expected storage layout
Reentrancy Loop State Drift	Intermediate state altered before completion (e.g., balance double-spend)
Misconfigured Self-Destruct	Destroyed contract leaves behind corrupted storage slots
Governance Takeover Write	Malicious proposal changes core system constants

🛡️ 3. Defenses Against Compromised State
Defense Strategy	Implementation Tip
✅ Storage Layout Lock	Use storage slot version hash to enforce expected layout
✅ Upgradeable Proxy Checker	Pre-deploy scripts to diff layout before upgrade
✅ State Consistency Invariants	Assert invariant conditions using forge invariant tests
✅ Timelocked Proposal Review	Delay any governance vote that touches critical storage
✅ Reentrancy + Write Guards	Use nonReentrant and separation of read/write logic
✅ SimStrategyAI Drift Tests	Fuzz replayed tx to detect unintended state changes

✅ 4. Complete Solidity Code: CompromisedStateGuard.sol
This system includes:

Core logic with tracked storage

Invariant assertion function

Recovery manager to restore state after compromise detection