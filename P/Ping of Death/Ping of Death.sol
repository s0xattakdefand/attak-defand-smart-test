// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* =================== PING OF DEATH TYPES =================== */

// 1️⃣ Fallback Loop Ping
contract FallbackLoop {
    fallback() external payable {
        (bool ok, ) = address(this).call(msg.data);
        require(ok);
    }
}

// 2️⃣ Recursive Gas Bomb
contract RecursivePing {
    uint256 public depthLimit = 5;

    function ping(uint256 depth) external {
        require(depth <= depthLimit, "Depth exceeded");
        if (depth > 0) {
            RecursivePing(address(this)).ping(depth - 1);
        }
    }
}

// 3️⃣ Oversize Calldata Ping
contract CalldataPing {
    event Ping(bytes data);

    function ping(bytes calldata payload) external {
        require(payload.length < 2048, "Too big");
        emit Ping(payload);
    }
}

// 4️⃣ Event Flood Ping
contract LogFlood {
    function ping() external {
        for (uint256 i = 0; i < 1000; i++) {
            emit Pinged(i);
        }
    }

    event Pinged(uint256 n);
}

// 5️⃣ Selector Echo Ping
contract EchoPing {
    address public next;

    constructor(address _next) {
        next = _next;
    }

    fallback() external payable {
        next.call(msg.data); // echo to next
    }
}

/* =================== ATTACK SIMULATORS =================== */

// Fallback spammer
contract PingSpammer {
    function attack(address target) external {
        target.call(hex"");
    }
}

// Calldata bomb
contract CalldataBomber {
    function blast(address target) external {
        bytes memory payload = new bytes(4000); // massive calldata
        target.call(abi.encodeWithSignature("ping(bytes)", payload));
    }
}

// Reentrancy echo
contract EchoChain {
    address public next;

    constructor(address _next) {
        next = _next;
    }

    function trigger() external {
        next.call(abi.encodeWithSignature("ping()"));
    }
}

/* =================== DEFENSE MODULES =================== */

// 🛡️ 1 Fallback Ping Rate Limiter
contract FallbackGuard {
    mapping(address => uint256) public lastPing;

    fallback() external {
        require(block.timestamp > lastPing[msg.sender] + 10, "Too soon");
        lastPing[msg.sender] = block.timestamp;
    }
}

// 🛡️ 2 Gas Usage Cap
contract GasLimitPing {
    function safePing() external {
        require(gasleft() > 20000, "Low gas");
        emit SafePing(msg.sender);
    }

    event SafePing(address from);
}

// 🛡️ 3 Calldata Size Checker
contract CalldataSizeCheck {
    function safe(bytes calldata input) external pure returns (bool) {
        return input.length < 1024;
    }
}

// 🛡️ 4 Log Emission Guard
contract EventThrottle {
    uint256 public limit = 10;
    mapping(address => uint256) public logs;

    event Log(address indexed user, uint256 index);

    function safeLog() external {
        require(logs[msg.sender] < limit, "Too many logs");
        logs[msg.sender]++;
        emit Log(msg.sender, logs[msg.sender]);
    }
}

// 🛡️ 5 Echo Depth Tracker
contract PingDepth {
    uint256 public depth;

    function ping(uint256 d) external {
        require(d + 1 > d, "Overflow");
        require(d < 5, "Too deep");
        depth = d;
        emit Depth(d);
    }

    event Depth(uint256 d);
}
