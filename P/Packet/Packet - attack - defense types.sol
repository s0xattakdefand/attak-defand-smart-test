// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========================================= */
/*           📦 TYPES OF PACKETS             */
/* ========================================= */

// 1️⃣ Payload Packet
contract PayloadPacket {
    event Executed(bytes4 selector, address sender);

    function execute(bytes calldata data) external {
        bytes4 sel = bytes4(data);
        emit Executed(sel, msg.sender);
        // mimic ABI dispatch or routing
    }
}

// 2️⃣ Relay Packet (L1 ↔ L2)
contract RelayPacket {
    event RelayReceived(address from, bytes data, uint256 timestamp);

    function receiveRelay(bytes calldata data) external {
        emit RelayReceived(msg.sender, data, block.timestamp);
    }
}

// 3️⃣ zk Proof Packet
contract ZKProofPacket {
    bytes32 public acceptedRoot;

    constructor(bytes32 _root) {
        acceptedRoot = _root;
    }

    function submitProof(bytes32[] calldata proof, bytes32 leaf) external view returns (bool) {
        bytes32 hash = leaf;
        for (uint i = 0; i < proof.length; i++) {
            hash = keccak256(abi.encodePacked(hash, proof[i]));
        }
        return hash == acceptedRoot;
    }
}

// 4️⃣ Multisig Packet
contract MultisigPacket {
    event Executed(address indexed signer, bytes data);

    function batchExecute(bytes[] calldata calls) external {
        for (uint i = 0; i < calls.length; i++) {
            emit Executed(msg.sender, calls[i]);
            // simulate call logic here
        }
    }
}

// 5️⃣ Oracle Packet
contract OraclePacketVerifier {
    address public trusted;
    event OracleSubmitted(bytes data, address signer);

    constructor(address _trusted) {
        trusted = _trusted;
    }

    function submit(bytes calldata data, bytes calldata sig) external {
        require(recover(data, sig) == trusted, "Untrusted source");
        emit OracleSubmitted(data, trusted);
    }

    function recover(bytes calldata data, bytes calldata sig) public pure returns (address) {
        bytes32 hash = keccak256(data);
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s);
    }
}

/* ========================================= */
/*        💥 PACKET ATTACK MODULES           */
/* ========================================= */

// 1️⃣ Payload Poisoning
contract PayloadPoisoning {
    fallback() external {
        // malformed input triggers fallback execution
    }
}

// 2️⃣ Replay Packet
contract ReplayPacketAttack {
    function replay(address target, bytes calldata packet) external {
        (bool ok, ) = target.call(packet);
        require(ok, "Replay failed");
    }
}

// 3️⃣ Packet Drift Injection
contract PacketDriftInjection {
    event DriftInjected(bytes4 selector);

    function drift(bytes calldata mutated) external {
        emit DriftInjected(bytes4(mutated));
    }
}

// 4️⃣ Cross-Relay Spoof
contract CrossRelaySpoof {
    function spoof(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "Spoof failed");
    }
}

// 5️⃣ Oracle Tamper Packet
contract OracleTamperAttack {
    function fake(bytes calldata forged, address target) external {
        (bool ok, ) = target.call(forged);
        require(ok, "Tamper failed");
    }
}

/* ========================================= */
/*        🛡 PACKET DEFENSE MODULES          */
/* ========================================= */

// 🛡️ 1 Packet Signature Check
contract PacketSigCheck {
    function validate(bytes calldata data, bytes calldata sig, address signer) external pure returns (bool) {
        bytes32 hash = keccak256(data);
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s) == signer;
    }
}

// 🛡️ 2 Nonce Tracker
contract NonceTracker {
    mapping(bytes32 => bool) public used;

    function use(bytes32 nonce) external {
        require(!used[nonce], "Replay detected");
        used[nonce] = true;
    }
}

// 🛡️ 3 Payload Structure Verifier
contract PayloadVerifier {
    function isValid(bytes calldata data) public pure returns (bool) {
        return data.length >= 4; // selector at least
    }
}

// 🛡️ 4 Relay Source Whitelist
contract RelayWhitelist {
    mapping(address => bool) public trusted;

    function setTrusted(address r, bool yes) external {
        trusted[r] = yes;
    }

    function verifyRelay(address sender) external view returns (bool) {
        return trusted[sender];
    }
}

// 🛡️ 5 Timestamp Bound Packet
contract TimestampBound {
    function check(uint256 ts) external view returns (bool) {
        require(block.timestamp <= ts + 5 minutes, "Expired packet");
        return true;
    }
}
