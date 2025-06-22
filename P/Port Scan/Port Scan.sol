// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== PORT SCAN ATTACK SIMULATORS ========== */

// 1️⃣ Brute Scan (Systematic selector scan)
contract SelectorScanner {
    function probe(address target, bytes4 selector) external {
        target.call(abi.encodePacked(selector));
    }
}

// 2️⃣ Entropy Drift Scanner
contract DriftScanner {
    function scan(address target, bytes4 seed, uint32 variation) external {
        bytes4 drift = seed ^ bytes4(variation);
        target.call(abi.encodePacked(drift));
    }
}

// 3️⃣ Fallback Ping Scanner
contract FallbackPinger {
    function ping(address target) external {
        target.call(hex""); // empty ping to fallback
    }
}

// 4️⃣ Gas Usage Analyzer (Oracle scan)
contract GasLeakScanner {
    function scan(address target, bytes4 selector) external returns (uint256) {
        uint256 gStart = gasleft();
        target.call(abi.encodePacked(selector));
        return gStart - gasleft(); // gas delta = fingerprint
    }
}

// 5️⃣ Relay Route Probe (for proxy/multiplexer)
contract RelayScanner {
    function relayScan(address proxy, bytes calldata payload) external {
        proxy.call(payload);
    }
}

/* ========== PORT SCAN DEFENSE MODULES ========== */

// 🛡️ 1 Selector Whitelist
contract PortGuard {
    mapping(bytes4 => bool) public approved;

    function allow(bytes4 s, bool ok) external {
        approved[s] = ok;
    }

    fallback() external {
        require(approved[msg.sig], "Blocked port");
    }
}

// 🛡️ 2 Entropy Bandwidth Filter
contract SelectorEntropyFilter {
    bytes4 public base = bytes4(keccak256("claim()"));

    fallback() external {
        require(hamming(msg.sig, base) < 12, "Drifted port");
    }

    function hamming(bytes4 a, bytes4 b) internal pure returns (uint8 d) {
        for (uint i = 0; i < 4; i++) d += pop(uint8(a[i] ^ b[i]));
    }

    function pop(uint8 x) internal pure returns (uint8 c) {
        for (; x > 0; x >>= 1) c += x & 1;
    }
}

// 🛡️ 3 Rate Limiter
contract PingLimiter {
    mapping(address => uint256) public last;

    fallback() external {
        require(block.timestamp > last[msg.sender] + 15, "Too fast");
        last[msg.sender] = block.timestamp;
    }
}

// 🛡️ 4 Fallback Trap Logger
contract FallbackTrap {
    event Trap(address indexed sender, bytes4 selector, uint256 block);

    fallback() external {
        emit Trap(msg.sender, msg.sig, block.number);
    }
}

// 🛡️ 5 Scan-Triggered Lockdown
contract AdaptiveFirewall {
    mapping(address => uint8) public strike;

    fallback() external {
        strike[msg.sender]++;
        require(strike[msg.sender] < 3, "Locked");
    }
}
