🧱 Term: Configuration Baseline — Web3 / Smart Contract Security Context
A Configuration Baseline is a formally defined set of secure, tested, and approved settings or parameters that a system must conform to. In Web3, this refers to the expected configuration state of smart contracts, DAOs, bridges, or security modules to ensure:

✅ Operational consistency,
✅ Security alignment,
✅ Compliance with audit standards (e.g., SWC, OWASP B-09, ChainSecurity)

📘 1. Types of Configuration Baselines in Web3
Baseline Type	Description
Access Control Baseline	Required roles, RBAC mappings, admin separation
Fee / Limit Baseline	Safe defaults for withdrawal limits, protocol fees, treasury caps
Security Module Baseline	Must-use protections (pause, reentrancy guard, replay lock)
Upgrade Control Baseline	Conditions for upgradeability, allowed implementation addresses
DAO Governance Baseline	Voting quorum %, delay windows, role vote caps
Oracle / Bridge Baseline	Trusted signer sets, relayer multisigs, zkVerifier roots

💥 2. Attacks from Deviating from the Baseline
Deviation Type	Risk Introduced
RBAC Misconfiguration	Unchecked admin role → asset drain or logic override
Fee Changed to 100%	DoS on users; attacker blocks system usage
Removed PauseGuard Module	System becomes unpausable under active exploit
Upgrade Path Opened	Backdoor logic or storage drift introduced
Governance Threshold Reduced	Single voter or flashloan can hijack DAO
Verifier Changed Without Review	Bridge or zkRollup compromised

🛡️ 3. Baseline Enforcement Strategies
Strategy	Solidity Implementation Practice
✅ Baseline Hash Commit	Store keccak256 of full config set and validate changes
✅ Config Approval Gating	Use onlyRole(BASELINE_ADMIN) or DAO votes to authorize updates
✅ Freeze Critical Params	Disable mutation of certain configs after audit
✅ Audit Trail on All Changes	Emit structured ConfigChanged logs with before/after
✅ SimStrategyAI Baseline Drift	Continuously test protocol state against approved configuration baseline

✅ 4. Solidity Code: ConfigurationBaselineEnforcer.sol
This contract:

Stores baseline config hash

Validates proposed changes against original

Emits events for drift and allows emergency reset