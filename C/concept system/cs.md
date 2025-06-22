🔐 Term: Concept System
1. Types of Concept System in Smart Contracts
A Concept System in Web3 smart contracts refers to the architectural or logical design that drives how modular behaviors, roles, and trust assumptions work together. Types include:

Type	Description
Monolithic System	All logic is embedded in a single contract (tight coupling).
Modular System	Composed of smaller units (logic, storage, governance) linked via interfaces.
Upgradable System	Built on proxy patterns like UUPS or Transparent proxies.
Permissioned System	Role-based or access-controlled functions.
Autonomous System	Operates without intervention (DAOs, AI agents).
Composable System	Integrates with external protocols like DeFi legos (e.g., Compound, Uniswap).

2. Attack Types on Concept Systems
Attack Type	Description
Monolith Injection	One failure affects all logic due to tight coupling.
Module Swap Attack	Swap logic modules maliciously in upgradable systems.
Permission Drift	Incorrect role logic leads to unauthorized execution.
Storage Collision	Improper layout in proxies can corrupt memory.
Composable Abuse	External protocol calls lead to reentrancy or mispricing.

3. Defense Types for Concept Systems
Defense Type	Description
Separation of Concerns	Keep logic, storage, and control clearly modular.
Role Guards	RBAC using AccessControl or custom modifiers.
Immutable Anchors	Use immutables or hashed configs for critical paths.
Upgrade Security	UUPS guards, rollback tests, version tracking.
Safe Composability