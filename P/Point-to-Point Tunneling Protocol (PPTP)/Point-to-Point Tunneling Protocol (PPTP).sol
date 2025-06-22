// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}

/* ========== PPTP TUNNEL TYPES ========== */

// 1️⃣ Stateless Tunnel (Simple Forward)
contract StatelessTunnel {
    address public destination;

    constructor(address dest) {
        destination = dest;
    }

    fallback() external payable {
        destination.call(msg.data); // forward all tunnel packets
    }
}

// 2️⃣ Stateful Tunnel (Tracks origin, nonce)
contract StatefulTunnel {
    struct Packet {
        address origin;
        uint256 nonce;
        bytes payload;
    }

    mapping(bytes32 => bool) public used;

    function tunnel(Packet calldata pkt) external {
        bytes32 hash = keccak256(abi.encode(pkt.origin, pkt.nonce, pkt.payload));
        require(!used[hash], "Replay");
        used[hash] = true;

        (bool ok, ) = address(this).call(pkt.payload);
        require(ok);
    }
}

// 3️⃣ SigTunnel (Signed packet unlock)
contract SignatureTunnel {
    function enter(bytes32 h, bytes calldata sig) external returns (address) {
        address signer = recover(h, sig);
        require(signer != address(0), "Invalid sig");
        return signer;
    }

    function recover(bytes32 h, bytes memory sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(h, v, r, s);
    }
}

// 4️⃣ zkProof Tunnel (Mocked)
contract zkTunnel {
    bytes32 public zkhash;

    function enter(bytes32 proof) external {
        require(proof == zkhash, "Bad zkProof");
    }

    function set(bytes32 p) external {
        zkhash = p;
    }
}

// 5️⃣ Tokenized Tunnel
contract ERC20Tunnel {
    IERC20 public token;
    address public receiver;

    constructor(IERC20 t, address r) {
        token = t;
        receiver = r;
    }

    function pass(uint256 amt) external {
        token.transferFrom(msg.sender, receiver, amt);
    }
}

/* ========== PPTP ATTACK MODULES ========== */

// Spoofed Packet
contract SpoofedEntry {
    function spoof(address target, bytes calldata data) external {
        target.call(data); // tries to impersonate
    }
}

// Replay Packet
contract ReplayAttack {
    function replay(StatefulTunnel t, StatefulTunnel.Packet calldata pkt) external {
        t.tunnel(pkt);
    }
}

// Proxy Drift Tunnel
contract DriftTunnel {
    address public logic;

    function setLogic(address l) external {
        logic = l;
    }

    fallback() external {
        logic.delegatecall(msg.data); // driftable
    }
}

/* ========== PPTP DEFENSE MODULES ========== */

// 🛡 Nonce Lock Guard
contract NonceGuard {
    mapping(address => uint256) public last;

    function check(address user, uint256 nonce) external {
        require(nonce > last[user], "Old nonce");
        last[user] = nonce;
    }
}

// 🛡 Tunnel Entry + Role Guard
contract TunnelACL {
    mapping(address => uint8) public zone;

    function set(address a, uint8 z) external {
        zone[a] = z;
    }

    modifier onlyZone(uint8 z) {
        require(zone[msg.sender] == z, "Zone mismatch");
        _;
    }

    function privilegedTunnel() external onlyZone(1) returns (bool) {
        return true;
    }
}

// 🛡 Logic Fingerprint Verifier
contract LogicHash {
    bytes32 public expected;

    function set(bytes32 h) external {
        expected = h;
    }

    function verify(address a) external view returns (bool) {
        return keccak256(abi.encodePacked(a.code)) == expected;
    }
}
