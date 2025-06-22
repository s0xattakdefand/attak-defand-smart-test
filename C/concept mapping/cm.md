### 🔐 Term: **Concept Mapping**

---

### 1. **Types of Concept Mapping in Smart Contracts**

In Solidity/Web3, **Concept Mapping** refers to the structured way of **associating concepts or entities** to one another (e.g., roles to addresses, tokens to metadata, or logic routes to selectors). It is often implemented using Solidity’s `mapping` type, but conceptually extends to semantic logic, composability, or inter-protocol mapping.

| Type                          | Description                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------- |
| **Address Mapping**           | Mapping entities like users or contracts to values (e.g., balances, roles).     |
| **Function Selector Mapping** | Maps selector (bytes4) to logic modules or permission sets.                     |
| **Role Mapping**              | Maps hashed roles to permissions or modules (RBAC).                             |
| **Semantic Mapping**          | Maps domain concepts (e.g., "admin", "vault") to dynamic behaviors or metadata. |
| **Protocol Mapping**          | Maps one protocol’s identifiers to another (e.g., cross-chain bridge IDs).      |

---

### 2. **Attack Types on Concept Mapping**

| Attack Type                     | Description                                                               |
| ------------------------------- | ------------------------------------------------------------------------- |
| **Uninitialized Mapping Abuse** | All keys are valid by default (zero-value), can lead to privilege hijack. |
| **Permission Overwrite**        | Mapping entry can be overwritten if not protected.                        |
| **Mapping Collision**           | Improper use of nested mappings can lead to overwritten state.            |
| **Logic Drift Mapping**         | Changing mappings during runtime to divert control to malicious logic.    |
| **Selector Injection**          | Mapping unvalidated `bytes4` selectors to fallback or malicious modules.  |

---

### 3. **Defense Types for Concept Mapping**

| Defense Type          | Description                                                               |
| --------------------- | ------------------------------------------------------------------------- |
| **Zero-Value Guards** | Require that mappings are initialized or non-zero to be considered valid. |
| **Role Protection**   | Use access control modifiers for mapping updates.                         |
| **Freeze Logic**      | Prevent critical mapping updates after deployment.                        |
| **Event Logging**     | Log all mapping changes for auditability.                                 |
| **Hash-Based Keys**   | Use `keccak256` for consistent and collision-resistant keys.              |

---

### 4. ✅ Solidity Code: Dynamic, Secure Concept Mapping System

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConceptMapping — Secure Dynamic Role & Logic Selector Mapping Registry

contract ConceptMapping {
    address public owner;

    /// Role => Address (e.g., role => module, handler, vault)
    mapping(bytes32 => address) public roleToAddress;

    /// Function Selector => Logic Module (Composable execution mapping)
    mapping(bytes4 => address) public selectorToLogic;

    /// Freeze individual role entries to prevent tampering
    mapping(bytes32 => bool) public frozenRoles;
    mapping(bytes4 => bool) public frozenSelectors;

    event RoleMapped(bytes32 indexed role, address indexed target);
    event SelectorMapped(bytes4 indexed selector, address indexed logic);
    event RoleFrozen(bytes32 indexed role);
    event SelectorFrozen(bytes4 indexed selector);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    /// --- Role Mapping (e.g., keccak256("VAULT_ADMIN")) => vault address --- ///
    function mapRole(bytes32 role, address target) external onlyOwner {
        require(!frozenRoles[role], "Role mapping frozen");
        roleToAddress[role] = target;
        emit RoleMapped(role, target);
    }

    function freezeRole(bytes32 role) external onlyOwner {
        frozenRoles[role] = true;
        emit RoleFrozen(role);
    }

    function getRoleMapping(bytes32 role) external view returns (address) {
        return roleToAddress[role];
    }

    /// --- Selector Mapping (e.g., bytes4(keccak256("mint(address,uint256)"))) => logic handler --- ///
    function mapSelector(bytes4 selector, address logic) external onlyOwner {
        require(!frozenSelectors[selector], "Selector mapping frozen");
        selectorToLogic[selector] = logic;
        emit SelectorMapped(selector, logic);
    }

    function freezeSelector(bytes4 selector) external onlyOwner {
        frozenSelectors[selector] = true;
        emit SelectorFrozen(selector);
    }

    function getSelectorMapping(bytes4 selector) external view returns (address) {
        return selectorToLogic[selector];
    }
}
```

---

### ✅ Key Use Cases

* **Role Mapping**
  → `keccak256("REWARD_MANAGER") → address of module`

* **Function Selector Mapping**
  → `bytes4(keccak256("execute(bytes)")) → address of logic handler`

* **Protocol Mapping**
  → Bridge function selectors to proxy logic across chains

---

### 🛡️ Security Measures

| Mechanism                         | Purpose                                     |
| --------------------------------- | ------------------------------------------- |
| `frozenRoles` / `frozenSelectors` | Locks mappings permanently post-deployment  |
| `keccak256` hashed roles          | Prevents role collision or spoofing         |
| Event Logging                     | Ensures traceable crosswalk changes         |
| Ownership Control                 | Only the contract owner can modify mappings |

---

Send your next term and I’ll return full breakdown + Solidity implementation again.
