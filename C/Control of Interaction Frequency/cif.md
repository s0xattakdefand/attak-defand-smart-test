### 🔐 Term: **Control of Interaction Frequency**

---

### 1. **What is Control of Interaction Frequency in Web3?**

**Control of Interaction Frequency** refers to mechanisms that **limit how often** an address, role, or module can **interact with a smart contract** or perform specific operations — to **prevent abuse**, **spam**, or **timing-based exploits** like frontrunning, flash bots, or reentrancy loops.

> 💡 It's like implementing **rate limits, cooldowns, or session windows** in smart contracts to **throttle behavior** and maintain system integrity.

---

### 2. **Types of Interaction Frequency Controls**

| Type                             | Description                                                           |
| -------------------------------- | --------------------------------------------------------------------- |
| **Per-Address Cooldown**         | Each address must wait a set duration before re-invoking a function.  |
| **Global Rate Limit**            | Limits how often the function can be executed network-wide.           |
| **Role-Based Frequency Control** | Some roles can bypass or have looser restrictions.                    |
| **Windowed Action Control**      | Function only available during specific time windows or block ranges. |
| **Session-Based Access**         | Interaction allowed within a session ID or signed proof expiry.       |

---

### 3. **Attack Types Prevented by Interaction Frequency Control**

| Attack Type                | Prevention Mechanism                                              |
| -------------------------- | ----------------------------------------------------------------- |
| **Spam Transactions**      | Per-address cooldown prevents contract flooding.                  |
| **MEV Frontrunning**       | Windowed or randomized delays reduce predictability.              |
| **Flash Loan Drain Loops** | Global rate limits block back-to-back calls in the same block.    |
| **Repeated Oracle Pulls**  | Per-address limit or time window restricts redundant fetches.     |
| **Voting/Claim Spam**      | Cooldowns stop duplicate vote/claim abuse in a governance system. |

---

### 4. ✅ Solidity Code: `InteractionFrequencyController.sol` — Implements Cooldowns and Rate Limits

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title InteractionFrequencyController — Restricts how often users/functions can be called
contract InteractionFrequencyController {
    address public owner;
    uint256 public globalCooldown = 10 minutes;
    uint256 public userCooldown = 5 minutes;
    uint256 public lastGlobalInteraction;

    mapping(address => uint256) public lastUserInteraction;

    event ActionTriggered(address indexed user, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier enforceGlobalCooldown() {
        require(
            block.timestamp >= lastGlobalInteraction + globalCooldown,
            "Global rate limit active"
        );
        _;
        lastGlobalInteraction = block.timestamp;
    }

    modifier enforceUserCooldown() {
        require(
            block.timestamp >= lastUserInteraction[msg.sender] + userCooldown,
            "User cooldown active"
        );
        _;
        lastUserInteraction[msg.sender] = block.timestamp;
    }

    constructor() {
        owner = msg.sender;
        lastGlobalInteraction = block.timestamp - globalCooldown;
    }

    /// 🔐 Function limited by both global + per-user cooldown
    function triggerAction() external enforceGlobalCooldown enforceUserCooldown {
        emit ActionTriggered(msg.sender, block.timestamp);
        // Insert sensitive logic here
    }

    /// 🔧 Adjust cooldowns
    function setCooldowns(uint256 globalDelay, uint256 userDelay) external onlyOwner {
        globalCooldown = globalDelay;
        userCooldown = userDelay;
    }

    /// 🔍 View time left before interaction allowed
    function getTimeLeft(address user) external view returns (uint256 userWait, uint256 globalWait) {
        userWait = block.timestamp < lastUserInteraction[user] + userCooldown
            ? (lastUserInteraction[user] + userCooldown - block.timestamp)
            : 0;
        globalWait = block.timestamp < lastGlobalInteraction + globalCooldown
            ? (lastGlobalInteraction + globalCooldown - block.timestamp)
            : 0;
    }
}
```

---

### ✅ What This Implements

| Control                   | Behavior                                                     |
| ------------------------- | ------------------------------------------------------------ |
| `enforceGlobalCooldown()` | Ensures that only 1 call can be made globally per N minutes. |
| `enforceUserCooldown()`   | Each user can only interact every N minutes.                 |
| `getTimeLeft()`           | UI integration or simulation check for cooldown window.      |
| `setCooldowns()`          | Dynamically tunable via DAO or owner logic.                  |

---

### 🔐 Real-World Use Cases

| Scenario                           | Frequency Control                                 |
| ---------------------------------- | ------------------------------------------------- |
| **Claiming DAO rewards**           | Only once per user per epoch (e.g., 1 hour).      |
| **Oracle price pulls**             | Only once per block or once per minute.           |
| **Bridge withdrawals**             | One withdrawal per user every 10 blocks.          |
| **Minting NFTs**                   | Throttle per-user mint rate to prevent gas wars.  |
| **Voting or proposal submissions** | One vote or proposal every X hours to limit spam. |

---

### 🧠 Summary

**Control of Interaction Frequency** in Web3:

* ✅ Prevents spam, drain, MEV bots, and timing abuse
* ✅ Applies to **users**, **roles**, or **entire systems**
* ✅ Enhances **stability, fairness**, and **auditability**
* ✅ Best used with time-based modifiers, randomness, or off-chain enforcement bots

---

📦 Combine with:

* `block.timestamp` or `block.number`–based windows
* EIP-712 signed session permits
* DAO voting to adjust thresholds dynamically
* Multi-chain replay guard to enforce frequency across L2s

---

Send your next **control, governance, or security term**, and I’ll break it down with types, threats, protections, and a complete Solidity implementation.
