### 🔐 Term: **Controlled Variable** (in Web3 / Solidity Smart Contracts)

---

### ✅ Definition

A **Controlled Variable** is a parameter or state variable in a smart contract whose access, mutation, or visibility is **intentionally restricted** to ensure consistent and secure behavior.

In the context of smart contracts, **controlled variables** help enforce:

* Access control
* Execution boundaries
* Upgrade safety
* Governance logic
* Time-locked changes

They are especially important for values that influence **financial logic, governance rules, or external integrations**.

---

### 🔣 1. Types of Controlled Variables

| Type                      | Description                                       |
| ------------------------- | ------------------------------------------------- |
| **Role-Gated Variable**   | Only specific roles can modify it                 |
| **Time-Locked Variable**  | Can be changed only after a delay                 |
| **Immutable Variable**    | Set once and locked forever                       |
| **Rate-Limited Variable** | Value can change within a defined delta or period |
| **Governance-Controlled** | Requires proposal + vote to update                |
| **Oracle-Bound Variable** | Depends on signed external input                  |

---

### 🚨 2. Attack Types on Controlled Variables

| Attack Type             | Target       | Description                                                 |
| ----------------------- | ------------ | ----------------------------------------------------------- |
| **Unauthorized Access** | Role-Gated   | Anyone can mutate critical variable                         |
| **Race Condition**      | Time-Locked  | Fast calls override the delay logic                         |
| **Upgrade Drift**       | Immutable    | Unexpected value shift in upgrade                           |
| **Governance Override** | Governance   | Malicious proposal sets extreme value                       |
| **Oracle Spoofing**     | Oracle-Bound | Fake signed value alters parameter                          |
| **Rate Jump Exploit**   | Rate-Limited | Update value far beyond threshold before limits are checked |

---

### 🛡️ 3. Defense Techniques for Controlled Variables

| Defense Strategy           | Use Case                                      |
| -------------------------- | --------------------------------------------- |
| ✅ `AccessControl`          | Restrict who can modify the variable          |
| ✅ `block.timestamp` Checks | Enforce time-based control                    |
| ✅ `immutable` Keyword      | Lock values post-deploy                       |
| ✅ Rate Check Guards        | Prevent sudden jumps                          |
| ✅ Offchain Signatures      | Bind variable update to a signed oracle input |
| ✅ Multi-sig Governance     | Secure variable changes via DAO               |

---

### ✅ 4. Complete Dynamic Solidity Example: `ControlledRateSetter.sol`

This contract:

* Limits variable update to admin role
* Includes rate-limited change (max delta allowed)
* Allows oracle-signed override for emergency

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ControlledRateSetter is AccessControl {
    using ECDSA for bytes32;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 public currentRate;
    uint256 public lastUpdated;
    address public trustedOracle;

    event RateChanged(uint256 oldRate, uint256 newRate);
    event OracleOverride(uint256 newRate, address by);

    constructor(uint256 initialRate, address oracle) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        currentRate = initialRate;
        trustedOracle = oracle;
        lastUpdated = block.timestamp;
    }

    modifier rateLimit(uint256 newRate) {
        require(block.timestamp >= lastUpdated + 1 hours, "Rate update cooldown");
        uint256 maxDelta = currentRate / 10; // max 10% change
        uint256 delta = newRate > currentRate ? newRate - currentRate : currentRate - newRate;
        require(delta <= maxDelta, "Rate change too large");
        _;
    }

    function updateRate(uint256 newRate) external onlyRole(ADMIN_ROLE) rateLimit(newRate) {
        uint256 oldRate = currentRate;
        currentRate = newRate;
        lastUpdated = block.timestamp;
        emit RateChanged(oldRate, newRate);
    }

    function emergencyOverride(uint256 newRate, bytes calldata sig) external {
        bytes32 digest = keccak256(abi.encodePacked(newRate, address(this))).toEthSignedMessageHash();
        require(digest.recover(sig) == trustedOracle, "Invalid oracle signature");

        currentRate = newRate;
        lastUpdated = block.timestamp;
        emit OracleOverride(newRate, msg.sender);
    }
}
```

---

### 🧠 Summary Table: Controlled Variable Mechanisms

| Control Type    | Mechanism              | Solidity Feature          |
| --------------- | ---------------------- | ------------------------- |
| Role-Gated      | `onlyRole()`           | `AccessControl`           |
| Rate-Limited    | Max % delta + cooldown | Modifier with time + math |
| Oracle-Override | Signed message         | `ECDSA.recover()`         |
| Time Constraint | `block.timestamp`      | Update delay              |

---

### 🔁 Next Steps?

Would you like to:

* Convert controlled variables into DAO proposals?
* Integrate with `TimelockController` for onchain governance delay?
* Visualize variable change history in a UI dashboard?

Let me know and I’ll generate the upgrade.
