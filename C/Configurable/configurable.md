⚙️ Term: Configurable — Web3 / Smart Contract Security Context
Configurable refers to any parameter, module, or behavior in a system that can be modified at runtime or deployment. In Web3 and smart contract security, configurability must be tightly controlled, audited, and safeguarded — as it can open attack surfaces if improperly exposed.

A configurable contract allows dynamic management of fees, limits, roles, plugins, or external addresses — but must balance flexibility with immutability, access control, and upgrade safety.

📘 1. Types of Configurable Elements in Web3
Configurable Element	Description
Fees / Rates / Thresholds	Protocol fees, DAO quorum %, price slippage guards
Role Permissions	Dynamic granting/revocation of operator/admin roles
Plugin / Module Addresses	Replaceable logic components (e.g., Safe plugins, Uniswap hooks)
Governance Settings	Time-lock delays, voting windows, quorum, proposal limits
Bridge / Oracle Routes	Change source relayers, endpoint addresses
ZK Circuit Parameters	Nullifier size, proof limits, root history windows

💥 2. Attack Vectors on Configurable Systems
Attack Type	Risk Description
Unauthorized Parameter Change	Malicious actor changes withdrawal limit, fee %, or vault cap
Plugin Drift Injection	New plugin/module changes behavior unexpectedly
Upgrade Escalation	Admin changes config to allow unrestricted upgrades
Governance Backdoor	Configurable voting power or quorum thresholds altered post-deploy
Router Override	Relayer or oracle config pointed to attacker-controlled endpoint

🛡️ 3. Defenses for Secure Configurable Contracts
Defense Strategy	Solidity Pattern or Practice
✅ Role-Based Access Control	Use onlyRole, AccessControl, or BitGuard for config setters
✅ Emit Config Change Logs	Transparently log every change (event ConfigChanged(...))
✅ Freeze Critical Configs	Make parameters immutable post-deployment if they never need changing
✅ Audit + Hash Snapshot	Register expected config hashes to validate at runtime
✅ DAO Proposal Gate	Route certain config updates through DAO vote or time-lock delay

✅ 4. Solidity Code: ConfigurableModule.sol
This contract:

Allows safe updates to configurable parameters

Enforces access control and logs changes

Demonstrates how to manage updatable values securely