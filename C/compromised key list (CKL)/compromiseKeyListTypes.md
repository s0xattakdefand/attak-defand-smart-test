🔐 Term: Compromised Key List (CKL) — Web3 / Smart Contract Security Context
A Compromised Key List (CKL) is a registry of known compromised private or public keys that should be revoked, blocked, or monitored to prevent unauthorized access or cryptographic misuse.

📘 1. Types of Compromised Key Lists (CKL)
Type	Description
On-Chain CKL	A smart contract that stores and enforces blocklists for compromised addresses
Off-Chain CKL	Maintained by auditors, oracles, or block explorers, consumed via API
ZK-Proven CKL	Users prove they’re not in a CKL using zero-knowledge proofs
Role-Based CKL	Separate CKLs per permission level (e.g., admin key CKL, relayer CKL)
Time-Bound CKL	Entries auto-expire or must be re-attested periodically

💥 2. Attacks on CKL Systems
Attack Type	Description
Key Reuse After Compromise	Malicious actors continue using a key not yet listed or enforced
CKL Bypass	Contracts don’t integrate CKL check, allowing compromised keys to interact
CKL Injection Attack	Attacker tricks governance into adding a safe key to the CKL
ZK Proof Spoofing	Fake “I am not compromised” proofs if nullifier hash is not validated
Race Condition on Key Ban	Exploiter acts before the CKL entry takes effect

🛡️ 3. Defenses for CKL
Defense Strategy	Implementation
✅ On-chain enforcement	Integrate CKL into all critical contracts (require(!isCompromised(msg.sender)))
✅ Timelocked revocation	Delay high-privilege access to allow community detection
✅ ZK exclusion proof	Use zkSNARK to prove key is not in CKL without revealing identity
✅ Multi-sig backup roles	In case one signer key is compromised, majority consensus overrides
✅ Governance-controlled CKL	Use DAO votes to review, validate, and manage CKL entries

🧱 4. Complete Solidity Code: CompromisedKeyList.sol
This contract manages:

CKL entry registration

Query checks

Enforcement example via SecureContract

Events and admin control