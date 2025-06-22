// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== PORT TYPES ========== */

// 1️⃣ Selector Port (Direct EVM entry)
contract SelectorPort {
    event Ping();
    event Pong();

    function ping() external {
        emit Ping();
    }

    function pong() external {
        emit Pong();
    }
}

// 2️⃣ Module Port Mapping (Dynamic Routing)
contract PortRouter {
    mapping(bytes4 => address) public ports;

    function setPort(bytes4 selector, address module) external {
        ports[selector] = module;
    }

    fallback() external {
        address module = ports[msg.sig];
        require(module != address(0), "Invalid port");
        (bool ok, ) = module.delegatecall(msg.data);
        require(ok);
    }
}

// 3️⃣ Access-Controlled Port
contract RBACPort {
    mapping(bytes4 => mapping(address => bool)) public canAccess;

    function setAccess(bytes4 port, address user, bool ok) external {
        canAccess[port][user] = ok;
    }

    fallback() external {
        require(canAccess[msg.sig][msg.sender], "Port Access Denied");
    }
}

// 4️⃣ Virtual Port Channels
contract PortChannel {
    mapping(uint256 => string) public channelName;

    function setChannel(uint256 port, string calldata name) external {
        channelName[port] = name;
    }

    function read(uint256 port) external view returns (string memory) {
        return channelName[port];
    }
}

// 5️⃣ Entropy-Locked Port
contract SelectorEntropyGuard {
    bytes4 public baseline = bytes4(keccak256("ping()"));

    fallback() external {
        require(hamming(msg.sig, baseline) <= 10, "Selector Drift Blocked");
    }

    function hamming(bytes4 a, bytes4 b) internal pure returns (uint8 d) {
        for (uint i = 0; i < 4; i++) d += pop(uint8(a[i] ^ b[i]));
    }

    function pop(uint8 x) internal pure returns (uint8 c) {
        for (; x > 0; x >>= 1) c += x & 1;
    }
}

/* ========== PORT-BASED ATTACKS ========== */

// Port Scanner
contract PortScanner {
    function scan(address target, bytes4 selector) external {
        target.call(abi.encodePacked(selector));
    }
}

// Selector Drift Injector
contract DriftInjector {
    function fuzz(address target, bytes4 seed, uint32 variant) external {
        bytes4 drift = seed ^ bytes4(variant);
        target.call(abi.encodePacked(drift));
    }
}

// Spoofed Injection
contract PortSpoofer {
    function spoof(address t) external {
        t.call(abi.encodeWithSignature("unknown()"));
    }
}

/* ========== DEFENSE MODULES ========== */

// 🛡️ Port Registry (Selector Binding)
contract PortRegistry {
    mapping(bytes4 => address) public binding;

    function bind(bytes4 sel, address logic) external {
        binding[sel] = logic;
    }

    function route(bytes calldata data) external {
        address to = binding[bytes4(data[:4])];
        require(to != address(0), "Unbound port");
        (bool ok, ) = to.delegatecall(data);
        require(ok);
    }
}

// 🛡️ Locked Port Config
contract PortLocker {
    mapping(bytes4 => bool) public locked;

    function lock(bytes4 sel) external {
        locked[sel] = true;
    }

    fallback() external {
        require(!locked[msg.sig], "Port is locked");
    }
}
