// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== ATTACK SIMULATION MODULES ========== */

// 1️⃣ Blind Selector Ping Scan
contract SelectorScanner {
    function probe(address target, bytes4 selector) external {
        bytes memory data = abi.encodePacked(selector);
        target.call(data);
    }
}

// 2️⃣ ABI Recon Pinger
contract ABIFuzzer {
    function fuzz(address target, bytes calldata encodedInput) external {
        (bool ok, ) = target.call(encodedInput);
        require(ok, "Failed");
    }
}

// 3️⃣ Role/Permission Ping
contract RoleProbe {
    function probeAdmin(address target) external {
        target.call(abi.encodeWithSignature("isAdmin(address)", msg.sender));
    }
}

// 4️⃣ Fallback Pinger
contract FallbackPing {
    function ping(address target) external {
        target.call(hex""); // trigger fallback
    }
}

// 5️⃣ Entropy Drift Scan
contract SelectorDriftPing {
    function drift(address target, bytes4 seed, uint256 variation) external {
        bytes4 selector = seed ^ bytes4(uint32(variation));
        target.call(abi.encodePacked(selector));
    }
}

/* ========== DEFENSE MODULES ========== */

// 🛡️ 1 Selector Whitelist
contract SelectorFirewall {
    mapping(bytes4 => bool) public approved;

    function set(bytes4 s, bool ok) external {
        approved[s] = ok;
    }

    fallback() external {
        require(approved[msg.sig], "Unknown selector");
    }
}

// 🛡️ 2 Entropy Drift Detector
contract SelectorEntropyGuard {
    bytes4 public baseline;

    constructor(bytes4 s) {
        baseline = s;
    }

    fallback() external {
        require(hamming(msg.sig, baseline) <= 10, "Selector drift too far");
    }

    function hamming(bytes4 a, bytes4 b) internal pure returns (uint8 d) {
        for (uint256 i = 0; i < 4; i++) {
            d += popCount(uint8(a[i] ^ b[i]));
        }
    }

    function popCount(uint8 x) internal pure returns (uint8 c) {
        for (; x > 0; x >>= 1) {
            c += x & 1;
        }
    }
}

// 🛡️ 3 Ping Rate Limiter
contract PingLimiter {
    mapping(address => uint256) public last;

    fallback() external {
        require(block.timestamp > last[msg.sender] + 15, "Ping too fast");
        last[msg.sender] = block.timestamp;
    }
}

// 🛡️ 4 Fallback Trap Logger
contract FallbackTrap {
    event FallbackPing(address indexed source, bytes4 selector);

    fallback() external {
        emit FallbackPing(msg.sender, msg.sig);
    }
}

// 🛡️ 5 Reentry Pattern Guard
contract GasProfileChecker {
    bool locked;

    modifier noReentry() {
        require(!locked, "Reentry");
        locked = true;
        _;
        locked = false;
    }

    function safePing() external noReentry {
        require(gasleft() > 20000, "Suspicious ping");
    }
}
