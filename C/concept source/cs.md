🔐 Term: Concept Source
1. Types of Concept Source in Smart Contracts
In the context of Solidity and Web3 security, a Concept Source refers to the origin or logic origin of a critical idea, contract behavior, or system assumption. Types include:

Type	Description
Hardcoded Source	Logic or values embedded directly in the contract (e.g., fixed address or parameters).
Oracle-Based Source	Relies on external feeds like Chainlink for real-world data.
User-Supplied Source	Relies on inputs or signed messages from users.
Modular Source	Logic derived from pluggable or upgradable contracts.
Governance-Driven Source	Values come from DAO voting or multisig consensus.

2. Attack Types on Concept Source
Attack Type	Description
Hardcoded Hijack	If the source is hardcoded and not upgradeable, attackers exploit its immutability.
Oracle Manipulation	Attackers manipulate oracles to feed false data into the contract.
Input Spoofing	Fake user input or signature-based injection to manipulate logic.
Governance Takeover	Compromised DAO or multisig feeding wrong logic.
Logic Drift in Upgrades	Incorrect upgrades or misconfigured proxies introduce flawed logic.

3. Defense Types for Concept Source
Defense Type	Description
Source Validation	Validate origin of data (e.g., tx.origin, signature recovery).
Decentralized Oracle Verification	Use multiple oracles or aggregator logic.
Access Control	Restrict who can feed or change logic sources.
Upgradability Guard	Use UUPS or Transparent Proxy patterns with logic versioning.
Signature Replay Protection