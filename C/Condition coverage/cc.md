### 🔐 Term: **Condition Coverage**

---

### 1. **Types of Condition Coverage in Smart Contracts**

**Condition coverage** is a form of code testing metric that measures how many **Boolean sub-expressions** in a conditional statement (e.g., `if`, `require`, `while`) have been evaluated **both to true and false**. In Solidity smart contracts, condition coverage ensures that all **logical branches and outcomes** are tested to catch potential logic flaws, especially in access control, state transitions, and fund-handling logic.

| Type                                             | Description                                                                                        |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| **Simple Condition Coverage**                    | Each Boolean condition in a compound expression is evaluated at least once for `true` and `false`. |
| **Multiple Condition Coverage (MCC)**            | Evaluates all possible combinations of Boolean conditions.                                         |
| **Modified Condition/Decision Coverage (MC/DC)** | Ensures each condition independently affects the decision outcome.                                 |
| **Branch Coverage (subset)**                     | Ensures each branch (true/false path) of a control structure is executed.                          |
| **Path Coverage (super-set)**                    | Evaluates all possible execution paths including all conditions.                                   |

---

### 2. **Attack Types Missed Without Proper Condition Coverage**

| Attack Type              | Description                                                     |
| ------------------------ | --------------------------------------------------------------- |
| **Unreachable Logic**    | Paths that never execute due to untested conditions.            |
| **Access Control Drift** | Certain roles or edge-case role states are never evaluated.     |
| **Unchecked Edge Cases** | Inputs that cause silent overflows or no-ops go undetected.     |
| **Unexpected Fallbacks** | Logic bypassed due to untested fallback paths or bad selectors. |
| **Time/Block Drift**     | Unverified time-based conditions allow early or late execution. |

---

### 3. **Defense Strategy: Full Condition Coverage Testing**

| Defense Type                         | Description                                                                     |
| ------------------------------------ | ------------------------------------------------------------------------------- |
| **Unit Test Every Branch**           | Each conditional must be tested with both `true` and `false` inputs.            |
| **Fuzz Testing with Symbolic Input** | Use tools like Foundry’s `forge-fuzz` to automatically explore condition paths. |
| **Custom Test Modifiers**            | Break out compound `require()` into isolated testable units.                    |
| **Test Boolean Decomposition**       | Test each condition separately (e.g., role check vs. state check).              |
| **CI Coverage Tracking**             | Use `forge coverage`, Hardhat plugins, or Slither to measure hit rate.          |

---

### 4. ✅ Solidity Code: Conditional Paths + Forge Test with 100% Condition Coverage

#### 🔹 `ConditionVault.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConditionVault — Demonstrates complex conditions with testable logic
contract ConditionVault {
    address public owner;
    bool public paused;
    mapping(address => bool) public whitelisted;
    uint256 public minDeposit;

    constructor(uint256 _minDeposit) {
        owner = msg.sender;
        minDeposit = _minDeposit;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier notPaused() {
        require(!paused, "Paused");
        _;
    }

    function setPaused(bool status) external onlyOwner {
        paused = status;
    }

    function setWhitelist(address user, bool allowed) external onlyOwner {
        whitelisted[user] = allowed;
    }

    function deposit() external payable notPaused {
        require(whitelisted[msg.sender], "Not whitelisted");
        require(msg.value >= minDeposit, "Below minimum");
    }
}
```

---

#### 🔹 `ConditionVault.t.sol` (Forge Unit Test File)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ConditionVault.sol";

contract ConditionVaultTest is Test {
    ConditionVault vault;
    address user = address(0xBEEF);

    function setUp() public {
        vault = new ConditionVault(1 ether);
        vault.setWhitelist(user, true);
        vm.deal(user, 10 ether);
    }

    function testDepositPassesWhenWhitelistedAndAmountOK() public {
        vm.prank(user);
        vault.deposit{value: 1 ether}();
    }

    function testRevertsWhenNotWhitelisted() public {
        address nonWhite = address(0xBAD);
        vm.deal(nonWhite, 1 ether);
        vm.expectRevert("Not whitelisted");
        vm.prank(nonWhite);
        vault.deposit{value: 1 ether}();
    }

    function testRevertsWhenBelowMinimum() public {
        vm.prank(user);
        vm.expectRevert("Below minimum");
        vault.deposit{value: 0.5 ether}();
    }

    function testRevertsWhenPaused() public {
        vault.setPaused(true);
        vm.expectRevert("Paused");
        vm.prank(user);
        vault.deposit{value: 1 ether}();
    }
}
```

---

### ✅ Condition Coverage Matrix for `deposit()` Logic

| Condition                 | True                     | False                               |
| ------------------------- | ------------------------ | ----------------------------------- |
| `!paused`                 | ✅ `testDepositPasses...` | ✅ `testRevertsWhenPaused()`         |
| `whitelisted[msg.sender]` | ✅ `testDepositPasses...` | ✅ `testRevertsWhenNotWhitelisted()` |
| `msg.value >= minDeposit` | ✅ `testDepositPasses...` | ✅ `testRevertsWhenBelowMinimum()`   |

✔️ All conditions hit both `true` and `false` — **100% condition coverage**

---

### 🧠 Summary

**Condition Coverage** ensures:

* Every **Boolean expression** is evaluated for both `true` and `false`
* Prevents bugs hiding in **untested logic**
* Must be used in all **security-sensitive logic** like roles, funds, upgrades, oracle calls

📦 Tools:

* `forge coverage` (Foundry)
* `solidity-coverage` (Hardhat)
* `slither` → `slither . --coverage`

---

Send the next term when ready — I’ll provide types, attack surfaces, defense strategies, and optimized Solidity code again.
