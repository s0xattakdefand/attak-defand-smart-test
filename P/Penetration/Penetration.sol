// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ============== PENETRATION TYPES ============== */

// 1️⃣ Entrypoint Penetration
contract EntryExploit {
    fallback() external payable {
        // attacker payload
        (bool ok, ) = msg.sender.call{value: 1 ether}("");
        require(ok);
    }
}

// 2️⃣ Role Escalation Penetration
contract RoleExploit {
    mapping(address => bool) public admin;

    function escalate() external {
        admin[msg.sender] = true;
    }
}

// 3️⃣ Signature Bypass
contract FakeSigPenetration {
    function bypass(bytes32 hash, bytes calldata sig) external pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s);
    }
}

// 4️⃣ Proxy Logic Penetration
contract ProxyExploit {
    address public logic;

    fallback() external {
        address impl = logic;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
}

// 5️⃣ Storage Drift Penetration
contract DriftStorageExploit {
    uint256 public ownerSlot;

    function overwrite(uint256 val) external {
        ownerSlot = val; // hijacks access control
    }
}

/* ============== PENETRATION DEFENSES ============== */

// 🛡️ 1 Entrypoint Filter
contract FallbackGuard {
    mapping(bytes4 => bool) public allowed;

    fallback() external {
        require(allowed[msg.sig], "Selector blocked");
    }

    function enable(bytes4 s, bool y) external {
        allowed[s] = y;
    }
}

// 🛡️ 2 Role Integrity Lock
contract RoleGuard {
    address public owner;

    function set(address user) external {
        require(msg.sender == owner, "Not authorized");
        owner = user;
    }
}

// 🛡️ 3 Sig Nonce Binding
contract SigNonceLock {
    mapping(address => uint256) public used;

    function validate(address signer, uint256 nonce) external {
        require(nonce > used[signer], "Replay");
        used[signer] = nonce;
    }
}

// 🛡️ 4 Logic Hash Checker
contract LogicHashChecker {
    bytes32 public expected;

    function set(bytes32 h) external {
        expected = h;
    }

    function verify(address logic) external view returns (bool) {
        return keccak256(abi.encodePacked(logic.code)) == expected;
    }
}

// 🛡️ 5 Slot Isolation Guard
contract SlotGuard {
    mapping(bytes32 => bytes32) private zone;

    function write(bytes32 k, bytes32 v) external {
        require(k != keccak256("owner.slot"), "Protected slot");
        zone[k] = v;
    }

    function read(bytes32 k) external view returns (bytes32) {
        return zone[k];
    }
}
