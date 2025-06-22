### 🔐 Term: **Zero Fill**

---

### 1. \*\*Types of Zero Fill in Smart Contracts

In the context of Solidity and smart contracts, **Zero Fill** refers to the **default initialization or padding of memory/storage variables with zeroes**. It also describes the behavior of uninitialized `mapping`, `array`, or `struct` slots where values return `0`, `false`, or `0x00…00` by default.

| Type                      | Description                                                                           |
| ------------------------- | ------------------------------------------------------------------------------------- |
| **Storage Zero Fill**     | Default value of an uninitialized storage slot (e.g., mapping returns 0 for any key). |
| **Memory Zero Fill**      | Memory segments start with zeroed bytes unless explicitly written.                    |
| **Calldata Zero Fill**    | Absent calldata fields implicitly considered zero when decoding loosely.              |
| **Return Data Zero Fill** | Functions returning empty or partial data implicitly pad with 0.                      |
| **Fallback Zero Fill**    | Fallback functions receiving unknown calls return zero values or no data.             |

---

### 2. **Attack Types Leveraging Zero Fill**

| Attack Type               | Description                                                                                                                 |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **Mapping Abuse**         | Attacker reads or manipulates `mapping[key]` expecting non-zero, but defaults to 0 and triggers logic (e.g., gains access). |
| **Unchecked Zero Access** | Functions operate on default zero values leading to faulty conditions or access.                                            |
| **Zero-Fill Reentrancy**  | Defaults are reused mid-execution, causing bypass during nested calls.                                                      |
| **Zero-Fill Bypass**      | Admin or whitelist checks incorrectly allow `address(0)` or `uint(0)`.                                                      |
| **Return Spoofing**       | Interfaces return zero-filled data enabling logical exploits (e.g., ERC20 `false` vs. `0x00...01` issue).                   |

---

### 3. **Defense Types Against Zero Fill Exploits**

| Defense Type                  | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| **Explicit Initialization**   | Always set critical variables (e.g., mappings, roles) explicitly.          |
| **Non-Zero Checks**           | Use `require(value != 0)` on role assignments or balance/ID logic.         |
| **Strict Return Handling**    | Use `bool success` return checks instead of assuming zero means fail/pass. |
| **Safe Address Check**        | Never allow `address(0)` as owner, receiver, or target.                    |
| **Fail-Closed Default Logic** | Assume zero equals no permission/false unless explicitly granted.          |

---

### 4. ✅ Solidity Code: Zero Fill Exploit Simulation + Mitigation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ZeroFillDefense — Demonstrates and defends against Zero Fill-based exploits

contract ZeroFillDefense {
    address public owner;
    mapping(address => uint256) public accessLevel;
    mapping(address => bool) public whitelist;

    event AccessGranted(address indexed user, uint256 level);
    event Whitelisted(address indexed user);
    event LogicExecuted(address indexed by, uint256 result);

    constructor() {
        owner = msg.sender;
        whitelist[owner] = true;
        accessLevel[owner] = 100;
    }

    /// ❌ Vulnerable: assumes any address with level > 0 is valid
    function vulnerableAccess(address user) external view returns (string memory) {
        if (accessLevel[user] > 0) {
            return "Granted";
        }
        return "Denied";
    }

    /// ✅ Fixed: explicitly deny if access level was never granted
    function secureAccess(address user) external view returns (string memory) {
        if (accessLevel[user] != 0 && whitelist[user]) {
            return "Granted";
        }
        return "Denied";
    }

    /// ❌ Vulnerable: anyone can call with address(0)
    function setOwner(address newOwner) external {
        require(newOwner != address(0), "Zero address");
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }

    /// ✅ Secure assignment with zero guard
    function setAccess(address user, uint256 level) external {
        require(msg.sender == owner, "Only owner");
        require(user != address(0), "Invalid address");
        require(level > 0, "Level must be non-zero");

        whitelist[user] = true;
        accessLevel[user] = level;

        emit AccessGranted(user, level);
        emit Whitelisted(user);
    }

    /// ✅ Defensive logic using zero-check
    function executeLogic(uint256 input) external returns (uint256) {
        require(input != 0, "Zero input rejected");

        uint256 result = input * 2;
        emit LogicExecuted(msg.sender, result);
        return result;
    }
}
```

---

### ✅ Defenses Demonstrated

| Exploit Type            | Mitigation                                      |
| ----------------------- | ----------------------------------------------- |
| Zero mapping values     | Require `accessLevel != 0 && whitelist == true` |
| Zero address ownership  | Explicit `require(user != address(0))`          |
| Zero-value calls        | Rejection of `input == 0`                       |
| Uninitialized privilege | No implicit permission based on mapping default |

---

### 🧠 Summary

* **Zero Fill** is default behavior in EVM.
* Assumptions around uninitialized values can **lead to privilege or logic flaws**.
* Always validate **non-zero, initialized values**, especially for:

  * Access control
  * Address-based permissions
  * Role-based mappings
  * Token balance logic
  * Function selector fallbacks

---

Send the next term when you're ready — each will follow this structure: **Types + Attacks + Defenses + Full Solidity Code**.
