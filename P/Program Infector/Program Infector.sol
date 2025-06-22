// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 1️⃣ Delegatecall Injector (Poisoned logic) ========== */
contract MaliciousLogic {
    event Infected(address user);

    function attack() public {
        emit Infected(msg.sender);
        // drain(), selfdestruct(), etc.
    }
}

contract VictimProxy {
    address public logic;

    constructor(address l) {
        logic = l;
    }

    fallback() external payable {
        (bool ok, ) = logic.delegatecall(msg.data);
        require(ok);
    }
}

/* ========== 2️⃣ Clone Factory Infector ========== */
contract CloneInfector {
    event CloneDeployed(address addr);

    function infect(bytes memory code) external {
        address deployed;
        assembly {
            deployed := create(0, add(code, 0x20), mload(code))
        }
        emit CloneDeployed(deployed);
    }
}

/* ========== 3️⃣ Slot-Based Upgrade Infector ========== */
contract PoisonUpgradeSlot {
    bytes32 internal constant SLOT = keccak256("upgrade.slot");

    function infect(address victim, address newLogic) external {
        assembly {
            sstore(SLOT, newLogic)
        }
    }
}

/* ========== 4️⃣ ABI Hook (Hidden Fallback Logic) ========== */
contract FallbackInfector {
    fallback() external payable {
        if (msg.sig == bytes4(keccak256("drain()"))) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }

    receive() external payable {}
}

/* ========== 🛡️ DEFENSE MODULES ========== */

// 🛡️ 1 Hash Fingerprint
contract IntegrityChecker {
    bytes32 public constant VALID_HASH = 0xabc123...;

    function validate(address target) external view returns (bool) {
        bytes32 codehash;
        assembly {
            codehash := extcodehash(target)
        }
        return codehash == VALID_HASH;
    }
}

// 🛡️ 2 Slot Lock
contract SlotLocker {
    address public logic;
    address public owner;

    constructor(address l) {
        logic = l;
        owner = msg.sender;
    }

    function upgrade(address l) external {
        require(msg.sender == owner, "Unauthorized");
        logic = l;
    }
}

// 🛡️ 3 ABI Whitelist
contract SelectorGuard {
    mapping(bytes4 => bool) public allowed;

    function set(bytes4 sel, bool ok) external {
        allowed[sel] = ok;
    }

    fallback() external {
        require(allowed[msg.sig], "Blocked selector");
    }
}
