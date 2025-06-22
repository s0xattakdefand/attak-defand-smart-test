// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ===================================== */
/*      📦 PACKET SWITCHED NETWORKS      */
/* ===================================== */

// 1️⃣ Basic Routing PSN
contract BasicRoutingPSN {
    mapping(bytes4 => address) public routes;

    function setRoute(bytes4 selector, address target) external {
        routes[selector] = target;
    }

    fallback() external payable {
        address target = routes[msg.sig];
        require(target != address(0), "No route");
        (bool ok, ) = target.call(msg.data);
        require(ok, "Routing failed");
    }
}

// 2️⃣ Multicast PSN
contract MulticastPSN {
    address[] public receivers;

    function addReceiver(address r) external {
        receivers.push(r);
    }

    function broadcast(bytes calldata data) external {
        for (uint i = 0; i < receivers.length; i++) {
            receivers[i].call(data);
        }
    }
}

// 3️⃣ zk-Verified PSN
contract zkVerifiedPSN {
    bytes32 public trustedRoot;

    function setRoot(bytes32 root) external {
        trustedRoot = root;
    }

    function routeWithProof(bytes32[] calldata proof, bytes32 leaf, bytes calldata data) external {
        bytes32 hash = leaf;
        for (uint i = 0; i < proof.length; i++) {
            hash = keccak256(abi.encodePacked(hash, proof[i]));
        }
        require(hash == trustedRoot, "Invalid proof");
        (bool ok, ) = address(this).call(data);
        require(ok);
    }
}

// 4️⃣ L1↔L2 Cross-Domain PSN
contract CrossDomainPSN {
    mapping(bytes32 => bool) public processed;

    function receivePacket(bytes32 id, bytes calldata payload) external {
        require(!processed[id], "Duplicate packet");
        processed[id] = true;
        (bool ok, ) = address(this).call(payload);
        require(ok);
    }
}

// 5️⃣ Entropy-Aware PSN
contract EntropyAwarePSN {
    event Routed(bytes4 indexed selector, uint8 entropy);

    function route(bytes calldata data) external {
        bytes4 sel = bytes4(data);
        uint8 ent = countBits(uint32(uint256(sel)));
        emit Routed(sel, ent);
    }

    function countBits(uint32 x) internal pure returns (uint8) {
        uint8 count;
        while (x > 0) {
            count += uint8(x & 1);
            x >>= 1;
        }
        return count;
    }
}

/* ===================================== */
/*        💥 PSN-BASED ATTACKS           */
/* ===================================== */

// 1️⃣ Selector Collision Packet
contract SelectorCollisionAttack {
    fallback() external {
        // Exploit selector collisions
    }
}

// 2️⃣ Packet Delay Injection
contract DelayInjection {
    function delayedExecute(address target, bytes calldata data, uint256 delay) external {
        require(block.timestamp > delay, "Too early");
        target.call(data);
    }
}

// 3️⃣ Multicast Flood
contract FloodAttack {
    function spam(address router, bytes calldata data, uint256 times) external {
        for (uint i = 0; i < times; i++) {
            router.call(data);
        }
    }
}

// 4️⃣ zkProof Drift Packet
contract DriftedZKPacket {
    function send(bytes32[] calldata fakeProof, bytes32 invalidLeaf, address target, bytes calldata callData) external {
        target.call(abi.encodeWithSelector(bytes4(keccak256("routeWithProof(bytes32[],bytes32,bytes)")), fakeProof, invalidLeaf, callData));
    }
}

// 5️⃣ Cross-Relay Echo Attack
contract EchoReplay {
    function replay(bytes32 id, bytes calldata data, address relay) external {
        relay.call(abi.encodeWithSelector(bytes4(keccak256("receivePacket(bytes32,bytes)")), id, data));
    }
}

/* ===================================== */
/*        🛡 PSN DEFENSE MODULES         */
/* ===================================== */

// 🛡️ 1 Selector Hash Validator
contract SelectorHashValidator {
    mapping(bytes4 => bool) public valid;

    function allow(bytes4 sel, bool yes) external {
        valid[sel] = yes;
    }

    fallback() external {
        require(valid[msg.sig], "Selector blocked");
    }
}

// 🛡️ 2 Packet Time Tracker
contract PacketTimeTracker {
    mapping(bytes32 => uint256) public timestamps;

    function register(bytes32 id) external {
        timestamps[id] = block.timestamp;
    }

    function isFresh(bytes32 id) public view returns (bool) {
        return block.timestamp - timestamps[id] <= 5 minutes;
    }
}

// 🛡️ 3 Multicast Receiver Limit
contract ReceiverLimit {
    address[] public receivers;
    uint256 public constant MAX = 10;

    function add(address r) external {
        require(receivers.length < MAX, "Too many receivers");
        receivers.push(r);
    }
}

// 🛡️ 4 zkProof Merkle Guard
contract zkProofGuard {
    bytes32 public root;

    function set(bytes32 r) external {
        root = r;
    }

    function verify(bytes32[] calldata proof, bytes32 leaf) external view returns (bool) {
        bytes32 h = leaf;
        for (uint i = 0; i < proof.length; i++) {
            h = keccak256(abi.encodePacked(h, proof[i]));
        }
        return h == root;
    }
}

// 🛡️ 5 Relay Replay Logger
contract RelayReplayLogger {
    mapping(bytes32 => bool) public seen;
    event Replayed(bytes32 indexed id, address sender);

    function log(bytes32 id) external {
        if (seen[id]) emit Replayed(id, msg.sender);
        seen[id] = true;
    }
}
