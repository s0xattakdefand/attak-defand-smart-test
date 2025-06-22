// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TCPDumpSuite.sol
/// @notice On‑chain analogues of common “TCP Dump” patterns:
///   Types: PacketCapture, BulkCapture, LogInjection, PrivacyFilter  
///   AttackTypes: SniffPackets, FloodCapture, InjectPayload, LeakSensitive  
///   DefenseTypes: AccessControl, RateLimit, HashPayload, PortFilter  

enum TCPDumpType       { PacketCapture, BulkCapture, LogInjection, PrivacyFilter }
enum TCPDumpAttackType { SniffPackets, FloodCapture, InjectPayload, LeakSensitive }
enum TCPDumpDefenseType{ AccessControl, RateLimit, HashPayload, PortFilter }

error TCPD__NotOwner();
error TCPD__TooMany();
error TCPD__BadPayload();
error TCPD__PortNotAllowed();

////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED PACKET CAPTURE
//    • Vulnerable: anyone can dump any packet
//    • Attack: attacker calls dumpPacket() to log raw data
//    • Defense: restrict to owner
////////////////////////////////////////////////////////////////////////
contract TCPDumpVuln1 {
    event Packet(address indexed src, address indexed dst, uint16 srcPort, uint16 dstPort, bytes payload);

    /// ❌ no access control – any caller logs raw packets
    function dumpPacket(address dst, uint16 srcPort, uint16 dstPort, bytes calldata payload) external {
        emit Packet(msg.sender, dst, srcPort, dstPort, payload);
    }
}

contract Attack_TCPDump1 {
    TCPDumpVuln1 public target;
    constructor(TCPDumpVuln1 _t) { target = _t; }

    /// attacker logs a spoofed packet
    function sniff(address dst, uint16 srcPort, uint16 dstPort, bytes calldata payload) external {
        // logs this packet event
        target.dumpPacket(dst, srcPort, dstPort, payload);
    }
}

contract TCPDumpSafe1 {
    address public owner;
    event Packet(address indexed src, address indexed dst, uint16 srcPort, uint16 dstPort, bytes payload);

    constructor() { owner = msg.sender; }

    /// ✅ only owner may capture packets
    function dumpPacket(address dst, uint16 srcPort, uint16 dstPort, bytes calldata payload) external {
        if (msg.sender != owner) revert TCPD__NotOwner();
        emit Packet(msg.sender, dst, srcPort, dstPort, payload);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) UNBOUNDED BULK CAPTURE (DoS)
//    • Vulnerable: no limit on number of packets per call
//    • Attack: floodDump() writes thousands of events
//    • Defense: cap bulk size
////////////////////////////////////////////////////////////////////////
contract TCPDumpVuln2 {
    event Packet(address indexed src, address indexed dst, uint16 srcPort, uint16 dstPort, bytes payload);

    function dumpBulk(address[] calldata dsts, uint16[] calldata srcPorts, uint16[] calldata dstPorts, bytes[] calldata payloads) external {
        for (uint i; i < dsts.length; i++) {
            emit Packet(msg.sender, dsts[i], srcPorts[i], dstPorts[i], payloads[i]);
        }
    }
}

contract Attack_TCPDump2 {
    TCPDumpVuln2 public target;
    constructor(TCPDumpVuln2 _t) { target = _t; }

    function flood(address[] calldata dsts, uint16[] calldata s, uint16[] calldata d, bytes[] calldata p) external {
        // floods dump with many packets
        target.dumpBulk(dsts, s, d, p);
    }
}

contract TCPDumpSafe2 {
    uint256 public constant MAX_BULK = 50;
    event Packet(address indexed src, address indexed dst, uint16 srcPort, uint16 dstPort, bytes payload);
    error TCPD__TooMany();

    function dumpBulk(address[] calldata dsts, uint16[] calldata srcPorts, uint16[] calldata dstPorts, bytes[] calldata payloads) external {
        if (dsts.length > MAX_BULK) revert TCPD__TooMany();
        for (uint i; i < dsts.length; i++) {
            emit Packet(msg.sender, dsts[i], srcPorts[i], dstPorts[i], payloads[i]);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) LOG INJECTION
//    • Vulnerable: logs raw payload strings → injection possible
//    • Attack: inject control sequences in payload
//    • Defense: log only hash of payload
////////////////////////////////////////////////////////////////////////
contract TCPDumpVuln3 {
    event PayloadLog(address indexed who, string payload);

    function logPayload(string calldata payload) external {
        emit PayloadLog(msg.sender, payload);
    }
}

contract Attack_TCPDump3 {
    TCPDumpVuln3 public target;
    constructor(TCPDumpVuln3 _t) { target = _t; }

    /// inject malicious log
    function inject(string calldata bad) external {
        target.logPayload(bad);
    }
}

contract TCPDumpSafe3 {
    event PayloadHash(address indexed who, bytes32 payloadHash);
    error TCPD__BadPayload();

    function logPayload(string calldata payload) external {
        if (bytes(payload).length > 1024) revert TCPD__BadPayload();
        emit PayloadHash(msg.sender, keccak256(bytes(payload)));
    }
}

////////////////////////////////////////////////////////////////////////
// 4) PRIVACY FILTERING
//    • Vulnerable: logs sensitive ports (e.g., 22, 80)
//    • Attack: read logs to leak SSH/HTTP traffic
//    • Defense: filter out well‑known ports
////////////////////////////////////////////////////////////////////////
contract TCPDumpVuln4 {
    event Packet(address indexed src, address indexed dst, uint16 srcPort, uint16 dstPort);

    function dumpPacket(address dst, uint16 srcPort, uint16 dstPort) external {
        emit Packet(msg.sender, dst, srcPort, dstPort);
    }
}

contract Attack_TCPDump4 {
    TCPDumpVuln4 public target;
    constructor(TCPDumpVuln4 _t) { target = _t; }

    function leak(address dst, uint16 sp, uint16 dp) external {
        target.dumpPacket(dst, sp, dp);
    }
}

contract TCPDumpSafe4 {
    event Packet(address indexed src, address indexed dst, uint16 srcPort, uint16 dstPort);
    error TCPD__PortNotAllowed();

    /// ✅ only log if both ports > 1024 (non‑privileged)
    function dumpPacket(address dst, uint16 srcPort, uint16 dstPort) external {
        if (srcPort <= 1024 || dstPort <= 1024) revert TCPD__PortNotAllowed();
        emit Packet(msg.sender, dst, srcPort, dstPort);
    }
}
