🔐 Term: Concept Type
1. Types of Concept Type in Smart Contracts
In Web3 and Solidity, a Concept Type refers to the fundamental classification of logic, structures, or design patterns used in contracts. It helps define how a smart contract behaves, interacts, and evolves. Types include:

Concept Type	Description
Static Type	Immutable logic and parameters, no upgrades.
Dynamic Type	Behavior can change at runtime (e.g., strategy pattern).
Composable Type	Designed to plug into or call other protocols (DeFi legos).
Upgradeable Type	Uses proxy patterns to separate storage and logic.
Modular Type	Functionalities split across deployable subcontracts or modules.
Role-Driven Type	Access and execution depend on assigned roles (RBAC).

2. Attack Types on Concept Types
Attack Type	Description
Static Entrapment	Locked logic can’t be patched if a vulnerability is found.
Dynamic Hijack	A logic pointer is redirected to malicious code.
Composable Abuse	Integration with external protocols exposes attack surfaces.
Storage Collision	Upgradeable types can corrupt storage if layout isn't preserved.
Role Misassignment	Improperly set or mutable roles allow privilege escalation.

3. Defense Types for Concept Types
Defense Type	Description
Immutability Safeguards	Lock critical values or use constructor-set immutables.
Access Control	Use AccessControl, Ownable, or custom role modifiers.
Safe Upgrade Mechanism	Use UUPS with rollback checks and strict ownership.
Storage Layout Lock	Use tools like StorageSlot to avoid collision.
Permission Verification	Require multi-sig or hashed proof to update logic pointers.