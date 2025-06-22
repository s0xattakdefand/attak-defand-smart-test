// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 7️⃣ Application Layer ========== */
contract AppLayer {
    event UserInput(address indexed user, string action);

    function submit(string calldata action) external {
        emit UserInput(msg.sender, action);
    }
}

/* ========== 6️⃣ Presentation Layer (Selector Codec) ========== */
contract SelectorCodec {
    function encode(string memory fn) external pure returns (bytes4) {
        return bytes4(keccak256(bytes(fn)));
    }

    function decode(bytes4 sel) external pure returns (string memory) {
        // Mock decode - in real life, ABI-based
        return sel == bytes4(keccak256("login()")) ? "login" : "unknown";
    }
}

/* ========== 5️⃣ Session Layer (Signature Sessions) ========== */
contract SessionAuth {
    mapping(address => bytes32) public current;

    function start(bytes32 session) external {
        current[msg.sender] = session;
    }

    function verify(bytes32 session) external view returns (bool) {
        return current[msg.sender] == session;
    }
}

/* ========== 4️⃣ Transport Layer (Relay Retry) ========== */
contract RetryRouter {
    mapping(bytes32 => bool) public seen;

    function relay(bytes32 id, address target, bytes calldata data) external {
        require(!seen[id], "Already relayed");
        seen[id] = true;
        (bool ok, ) = target.call(data);
        require(ok);
    }
}

/* ========== 3️⃣ Network Layer (Router Map) ========== */
contract RouteMap {
    mapping(address => address) public link;

    function connect(address a, address b) external {
        link[a] = b;
    }

    function nextHop(address a) external view returns (address) {
        return link[a];
    }
}

/* ========== 2️⃣ Data Link Layer (Role-MAC Mapping) ========== */
contract RoleMAC {
    mapping(address => bytes6) public mac;
    mapping(bytes6 => string) public role;

    function bind(address user, bytes6 addr, string calldata roleName) external {
        mac[user] = addr;
        role[addr] = roleName;
    }

    function getRole(address u) external view returns (string memory) {
        return role[mac[u]];
    }
}

/* ========== 1️⃣ Physical Layer (Calldata Signal) ========== */
contract CalldataSignal {
    event Signal(uint256 gasUsed, uint256 size);

    fallback() external {
        emit Signal(gasleft(), msg.data.length);
    }
}
