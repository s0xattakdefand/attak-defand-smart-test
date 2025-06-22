// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WindumpSuite.sol
/// @notice Four “Windump” patterns illustrating common pitfalls in on‑chain packet
///         capture on Windows‑style interfaces and hardened defenses.

enum WindumpType         { PacketCapture, BulkCapture, LogInjection, PortFilter }
enum WindumpAttackType   { SniffPackets, FloodCapture, InjectPayload, LeakSensitive }
enum WindumpDefenseType  { AccessControl, RateLimit, HashPayload, PortFilter }

error WIND__NotOwner();
error WIND__TooMany();
error WIND__BadPayload();
error WIND__PortNotAllowed();

////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED PACKET CAPTURE
//
//    • Vulnerable: anyone can capture packets
//    • Attack: SniffPackets
//    • Defense: AccessControl
////////////////////////////////////////////////////////////////////////
contract WindumpVuln1 {
    event Packet(
        address indexed capturer,
        address indexed src,
        uint16           srcPort,
        uint16           dstPort,
        bytes            payload,
        WindumpAttackType attack
    );

    function capture(
        address src,
        uint16 srcPort,
        uint16 dstPort,
        bytes calldata payload
    ) external {
        emit Packet(msg.sender, src, srcPort, dstPort, payload, WindumpAttackType.SniffPackets);
    }
}

contract Attack_Windump1 {
    WindumpVuln1 public target;
    constructor(WindumpVuln1 _t) { target = _t; }

    function sniff(address src, uint16 sp, uint16 dp, bytes calldata p) external {
        target.capture(src, sp, dp, p);
    }
}

contract WindumpSafe1 {
    address public owner;
    event Packet(
        address indexed capturer,
        address indexed src,
        uint16           srcPort,
        uint16           dstPort,
        bytes            payload,
        WindumpDefenseType defense
    );

    constructor() { owner = msg.sender; }

    function capture(
        address src,
        uint16 srcPort,
        uint16 dstPort,
        bytes calldata payload
    ) external {
        if (msg.sender != owner) revert WIND__NotOwner();
        emit Packet(msg.sender, src, srcPort, dstPort, payload, WindumpDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) UNBOUNDED BULK CAPTURE (DoS)
//
//    • Vulnerable: no limit on bulk size
//    • Attack: FloodCapture
//    • Defense: RateLimit
////////////////////////////////////////////////////////////////////////
contract WindumpVuln2 {
    event BulkPacket(
        address indexed capturer,
        address indexed src,
        uint16           srcPort,
        uint16           dstPort,
        bytes            payload,
        WindumpAttackType attack
    );

    function captureBulk(
        address[] calldata srcs,
        uint16[]  calldata srcPorts,
        uint16[]  calldata dstPorts,
        bytes[]   calldata payloads
    ) external {
        for (uint i = 0; i < srcs.length; i++) {
            emit BulkPacket(msg.sender, srcs[i], srcPorts[i], dstPorts[i], payloads[i], WindumpAttackType.FloodCapture);
        }
    }
}

contract Attack_Windump2 {
    WindumpVuln2 public target;
    constructor(WindumpVuln2 _t) { target = _t; }

    function flood(
        address[] calldata srcs,
        uint16[]  calldata sps,
        uint16[]  calldata dps,
        bytes[]   calldata ps
    ) external {
        target.captureBulk(srcs, sps, dps, ps);
    }
}

contract WindumpSafe2 {
    uint256 public constant MAX_BULK = 50;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    event BulkPacket(
        address indexed capturer,
        address indexed src,
        uint16           srcPort,
        uint16           dstPort,
        bytes            payload,
        WindumpDefenseType defense
    );
    error WIND__TooMany();

    function captureBulk(
        address[] calldata srcs,
        uint16[]  calldata srcPorts,
        uint16[]  calldata dstPorts,
        bytes[]   calldata payloads
    ) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender] += srcs.length;
        if (countInBlock[msg.sender] > MAX_BULK) revert WIND__TooMany();

        for (uint i = 0; i < srcs.length; i++) {
            emit BulkPacket(msg.sender, srcs[i], srcPorts[i], dstPorts[i], payloads[i], WindumpDefenseType.RateLimit);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) LOG INJECTION VIA PAYLOAD
//
//    • Vulnerable: logs raw payload, allows injection
//    • Attack: InjectPayload
//    • Defense: HashPayload
////////////////////////////////////////////////////////////////////////
contract WindumpVuln3 {
    event PayloadLog(address indexed capturer, string payload, WindumpAttackType attack);

    function logPayload(string calldata payload) external {
        emit PayloadLog(msg.sender, payload, WindumpAttackType.InjectPayload);
    }
}

contract Attack_Windump3 {
    WindumpVuln3 public target;
    constructor(WindumpVuln3 _t) { target = _t; }

    function inject(string calldata payload) external {
        target.logPayload(payload);
    }
}

contract WindumpSafe3 {
    event PayloadHash(address indexed capturer, bytes32 payloadHash, WindumpDefenseType defense);
    error WIND__BadPayload();

    function logPayload(string calldata payload) external {
        if (bytes(payload).length > 1024) revert WIND__BadPayload();
        emit PayloadHash(msg.sender, keccak256(bytes(payload)), WindumpDefenseType.HashPayload);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) PORT FILTERING
//
//    • Vulnerable: logs all ports, leaking privileged traffic
//    • Attack: LeakSensitive
//    • Defense: PortFilter
////////////////////////////////////////////////////////////////////////
contract WindumpVuln4 {
    event PacketInfo(address indexed capturer, uint16 srcPort, uint16 dstPort, WindumpAttackType attack);

    function captureInfo(uint16 srcPort, uint16 dstPort) external {
        emit PacketInfo(msg.sender, srcPort, dstPort, WindumpAttackType.LeakSensitive);
    }
}

contract Attack_Windump4 {
    WindumpVuln4 public target;
    constructor(WindumpVuln4 _t) { target = _t; }

    function leak(uint16 sp, uint16 dp) external {
        target.captureInfo(sp, dp);
    }
}

contract WindumpSafe4 {
    event PacketInfo(address indexed capturer, uint16 srcPort, uint16 dstPort, WindumpDefenseType defense);
    error WIND__PortNotAllowed();

    /// only log non‑privileged ports (>1024)
    function captureInfo(uint16 srcPort, uint16 dstPort) external {
        if (srcPort <= 1024 || dstPort <= 1024) revert WIND__PortNotAllowed();
        emit PacketInfo(msg.sender, srcPort, dstPort, WindumpDefenseType.PortFilter);
    }
}
