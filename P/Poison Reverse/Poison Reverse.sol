// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ================== POISON REVERSE TYPES ================== */

// 1️⃣ Route Back Nullifier
contract PoisonRoute {
    mapping(address => address) public lastHop;

    function enter(address from) external {
        require(lastHop[msg.sender] != from, "PoisonReverse: loop detected");
        lastHop[from] = msg.sender;
    }
}

// 2️⃣ Selector Reversal Poison
contract SelectorPoisonMap {
    mapping(bytes4 => bool) public poisoned;

    function mark(bytes4 sel, bool isBad) external {
        poisoned[sel] = isBad;
    }

    fallback() external {
        require(!poisoned[msg.sig], "Poisoned selector");
    }
}

// 3️⃣ Reverse Tunnel Sentinel
contract TunnelSentinel {
    mapping(address => bool) public active;

    modifier lock() {
        require(!active[msg.sender], "Reverse loop");
        active[msg.sender] = true;
        _;
        active[msg.sender] = false;
    }

    function tunnelCall(address target, bytes calldata data) external lock {
        (bool ok, ) = target.call(data);
        require(ok);
    }
}

// 4️⃣ Relay Chain Poison Flag
contract ChainPathLogger {
    mapping(address => bool) public used;
    mapping(address => uint256) public timestamp;

    function log(address h) external {
        require(!used[h], "PoisonReverse: used hop");
        used[h] = true;
        timestamp[h] = block.number;
    }
}

// 5️⃣ Loop-Aware Transfer Blocker
contract TransferBounceBlocker {
    mapping(address => uint256) public lastBlock;

    function send() external {
        require(block.number != lastBlock[msg.sender], "PoisonReverse: repeat sender");
        lastBlock[msg.sender] = block.number;
    }

    receive() external payable {}
}
