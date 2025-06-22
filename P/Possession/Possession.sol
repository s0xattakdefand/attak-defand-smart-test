// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== PORTSCAN ATTACK SIMULATORS ========== */

// 1️⃣ Brute Scanner
contract SelectorBrute {
    function scan(address target, bytes4 selector) external {
        target.call(abi.encodePacked(selector));
    }
}

// 2️⃣ Drift Scanner
contract SelectorDrifter {
    function fuzz(address target, bytes4 base, uint32 variant) external {
        bytes4 drift = base ^ bytes4(variant);
        target.call(abi.encodePacked(drift));
    }
}

// 3️⃣ ABI Mutator
contract ABIProbe {
    function fuzz(address target, bytes calldata data) external {
        target.call(data);
    }
}

// 4️⃣ Fallback Ping
contract PingFallback {
    function ping(address t) external {
        t.call(hex"");
    }
}

/* ========== DEFENSIVE MODULES ========== */

// 🛡️ 1 Selector Whitelist
contract SelectorFirewall {
    mapping(bytes4 => bool) public approved;

    function allow(bytes4 sel, bool ok) external {
        approved[sel] = ok;
    }

    fallback() external {
        require(approved[msg.sig], "Selector blocked");
    }
}

// 🛡️ 2 Entropy Drift Guard
contract EntropySelectorBlocker {
    bytes4 constant baseline = bytes4(keccak256("claim()"));

    fallback() external {
        require(hamming(msg.sig, baseline) < 8, "Drift blocked");
    }

    function hamming(bytes4 a, bytes4 b) internal pure returns (uint8 d) {
        for (uint i = 0; i < 4; i++) d += pop(uint8(a[i] ^ b[i]));
    }

    function pop(uint8 x) internal pure returns (uint8 c) {
        for (; x > 0; x >>= 1) c += x & 1;
    }
}

// 🛡️ 3 Rate Limiter (per caller)
contract ScanLimiter {
    mapping(address => uint256) public lastPing;

    fallback() external {
        require(block.timestamp > lastPing[msg.sender] + 15, "Too fast");
        lastPing[msg.sender] = block.timestamp;
    }
}

// 🛡️ 4 Fallback Trap Logger
contract FallbackLogger {
    event FallbackPing(address indexed from, bytes4 selector, uint256 blockNum);

    fallback() external {
        emit FallbackPing(msg.sender, msg.sig, block.number);
    }
}

// 🛡️ 5 Adaptive Lockdown
contract AdaptiveFirewall {
    mapping(address => uint8) public strikes;

    fallback() external {
        strikes[msg.sender]++;
        require(strikes[msg.sender] < 3, "Firewall triggered");
    }
}
