// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ================= POLYMORPHISM TYPES ================= */

// 1️⃣ Function Override Polymorphism
contract Base {
    function speak() public pure virtual returns (string memory) {
        return "Base";
    }
}

contract Child is Base {
    function speak() public pure override returns (string memory) {
        return "Child";
    }
}

// 2️⃣ Abstract Interface Execution
interface IAnimal {
    function sound() external view returns (string memory);
}

contract Cat is IAnimal {
    function sound() external pure returns (string memory) {
        return "Meow";
    }
}

contract Dog is IAnimal {
    function sound() external pure returns (string memory) {
        return "Woof";
    }
}

// 3️⃣ Selector Morphing via Proxy
contract ProxyPolymorph {
    address public logic;

    constructor(address l) {
        logic = l;
    }

    fallback() external payable {
        (bool ok, ) = logic.delegatecall(msg.data);
        require(ok);
    }
}

// 4️⃣ Payload-Based Polymorphism
contract DynamicRouter {
    event Response(string action);

    function route(bytes calldata input) external {
        if (keccak256(input) == keccak256("ping")) {
            emit Response("PONG");
        } else {
            emit Response("UNKNOWN");
        }
    }
}

// 5️⃣ Dynamic Logic Injection
contract LogicInjection {
    address public logic;

    function set(address l) external {
        logic = l;
    }

    function exec(bytes calldata d) external {
        (bool ok, ) = logic.delegatecall(d);
        require(ok);
    }
}

/* ================= ATTACKS ================= */

// Interface Trap
contract FakeDog is IAnimal {
    function sound() external pure returns (string memory) {
        return "Hacked";
    }
}

// Selector Drift
contract DriftAttack {
    function drift(address target, bytes4 sel) external {
        target.call(abi.encodePacked(sel));
    }
}

// Proxy Swap Logic
contract MaliciousLogic {
    function speak() public pure returns (string memory) {
        return "Hijacked";
    }
}

/* ================= DEFENSE MODULES ================= */

// 🛡️ 1 Selector Hash Guard
contract SelectorGuard {
    bytes4 public allowed = bytes4(keccak256("speak()"));

    fallback() external {
        require(msg.sig == allowed, "Selector mismatch");
    }
}

// 🛡️ 2 Interface Compliance Guard
interface ITrusted {
    function speak() external view returns (string memory);
}

contract InterfaceValidator {
    function isValid(address a) public view returns (bool) {
        try ITrusted(a).speak() returns (string memory) {
            return true;
        } catch {
            return false;
        }
    }
}

// 🛡️ 3 Upgrade Auth Guard
contract Upgradeable {
    address public logic;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function upgrade(address l) external {
        require(msg.sender == admin, "Only admin");
        logic = l;
    }
}
