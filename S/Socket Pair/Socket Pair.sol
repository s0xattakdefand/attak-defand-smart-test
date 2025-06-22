// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SocketPairsSuite.sol
/// @notice Four “Socket Pair” patterns illustrating common pitfalls in managing
///         (srcIP, srcPort, dstIP, dstPort) pairings on‑chain, plus hardened defenses.

error SOP__NotOwner();
error SOP__TooManyPairs();
error SOP__PairExpired();
error SOP__BadDetails();

struct Pair { 
    address owner; 
    uint16  srcPort; 
    uint16  dstPort; 
    uint256 createdAt; 
}

////////////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED PAIR BINDING
//
//   • Vulnerable: anyone can bind or overwrite any socket pair record
//   • Attack: hijack victim’s socket pairing
//   • Defense: only the creator may bind or overwrite
////////////////////////////////////////////////////////////////////////////////
contract SocketPairVuln1 {
    mapping(bytes32 => Pair) public pairs; // key = hash(srcPort,dstPort)

    function bindPair(uint16 srcPort, uint16 dstPort) external {
        bytes32 key = keccak256(abi.encodePacked(srcPort, dstPort));
        // ❌ no access control: overwrites existing
        pairs[key] = Pair(msg.sender, srcPort, dstPort, block.timestamp);
    }
}

contract Attack_SocketPair1 {
    SocketPairVuln1 public router;
    constructor(SocketPairVuln1 _r) { router = _r; }

    function hijack(uint16 victimSrc, uint16 victimDst) external {
        // attacker overwrites victim’s binding
        router.bindPair(victimSrc, victimDst);
    }
}

contract SocketPairSafe1 {
    mapping(bytes32 => Pair) public pairs;
    error SOP__NotOwner();

    function bindPair(uint16 srcPort, uint16 dstPort) external {
        bytes32 key = keccak256(abi.encodePacked(srcPort, dstPort));
        Pair memory p = pairs[key];
        if (p.owner != address(0) && p.owner != msg.sender) {
            revert SOP__NotOwner();
        }
        pairs[key] = Pair(msg.sender, srcPort, dstPort, block.timestamp);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) PAIR DETAILS SNIFFING
//
//   • Vulnerable: emits clear-text pair info in events
//   • Attack: off‑chain listener reads src/dst ports
//   • Defense: emit only hash of the tuple
////////////////////////////////////////////////////////////////////////////////
contract SocketPairVuln2 {
    event Bound(address indexed who, uint16 srcPort, uint16 dstPort);

    function bindPair(uint16 srcPort, uint16 dstPort) external {
        emit Bound(msg.sender, srcPort, dstPort);
    }
}

contract Attack_SocketPair2 {
    SocketPairVuln2 public router;
    constructor(SocketPairVuln2 _r) { router = _r; }

    function bindAndSniff(uint16 s, uint16 d) external {
        router.bindPair(s, d);
        // off‑chain sees event with s and d
    }
}

contract SocketPairSafe2 {
    event BoundHash(address indexed who, bytes32 pairHash);
    error SOP__BadDetails();

    function bindPair(uint16 srcPort, uint16 dstPort) external {
        // sanity check ports
        if (srcPort == 0 || dstPort == 0) revert SOP__BadDetails();
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, srcPort, dstPort));
        emit BoundHash(msg.sender, hash);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) PAIR CREATION FLOOD (DoS)
//
//   • Vulnerable: unlimited pairs per user → storage exhaustion
//   • Attack: flood bindPair to exhaust gas/storage
//   • Defense: cap pairs per user
////////////////////////////////////////////////////////////////////////////////
contract SocketPairVuln3 {
    mapping(address => bytes32[]) public myPairs;

    function bindPair(uint16 srcPort, uint16 dstPort) external {
        bytes32 key = keccak256(abi.encodePacked(srcPort, dstPort));
        myPairs[msg.sender].push(key);
    }
}

contract Attack_SocketPair3 {
    SocketPairVuln3 public router;
    constructor(SocketPairVuln3 _r) { router = _r; }

    function flood(uint16 s, uint16 d, uint256 n) external {
        for (uint i = 0; i < n; i++) {
            router.bindPair(s, d);
        }
    }
}

contract SocketPairSafe3 {
    mapping(address => bytes32[]) public myPairs;
    uint256 public constant MAX_PAIRS = 10;
    error SOP__TooManyPairs();

    function bindPair(uint16 srcPort, uint16 dstPort) external {
        bytes32 key = keccak256(abi.encodePacked(srcPort, dstPort));
        if (myPairs[msg.sender].length >= MAX_PAIRS) {
            revert SOP__TooManyPairs();
        }
        myPairs[msg.sender].push(key);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) STALE PAIR EXPIRY
//
//   • Vulnerable: pairs never expire → stale mappings persist
//   • Attack: stale pair remains indefinitely
//   • Defense: enforce TTL and reject expired lookups
////////////////////////////////////////////////////////////////////////////////
contract SocketPairVuln4 {
    mapping(bytes32 => Pair) public pairs;

    function bindPair(uint16 srcPort, uint16 dstPort) external {
        bytes32 key = keccak256(abi.encodePacked(srcPort, dstPort));
        pairs[key] = Pair(msg.sender, srcPort, dstPort, block.timestamp);
    }
    function lookup(uint16 srcPort, uint16 dstPort) external view returns (address) {
        bytes32 key = keccak256(abi.encodePacked(srcPort, dstPort));
        return pairs[key].owner;
    }
}

contract SocketPairSafe4 {
    mapping(bytes32 => Pair) public pairs;
    uint256 public constant TTL = 1 hours;
    error SOP__PairExpired();

    function bindPair(uint16 srcPort, uint16 dstPort) external {
        bytes32 key = keccak256(abi.encodePacked(srcPort, dstPort));
        pairs[key] = Pair(msg.sender, srcPort, dstPort, block.timestamp);
    }

    function lookup(uint16 srcPort, uint16 dstPort) external view returns (address) {
        bytes32 key = keccak256(abi.encodePacked(srcPort, dstPort));
        Pair memory p = pairs[key];
        if (block.timestamp > p.createdAt + TTL) {
            revert SOP__PairExpired();
        }
        return p.owner;
    }
}
