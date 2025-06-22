// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title UDPScanSuite.sol
/// @notice On‑chain analogues of “UDP Scan” patterns with common pitfalls
///         and hardened defenses.

enum UDPScanType           { PingSweep, PortScan }
enum UDPScanAttackType     { SweepFlood, Fragmentation }
enum UDPScanDefenseType    { RateLimitICMP, UniformResponse }

error UDP__TooManyScans();
error UDP__NoResponse();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE UDP SCAN LOGGER
///
///    • anyone may scan any port and log raw responses
///    • AttackType: SweepFlood
///─────────────────────────────────────────────────────────────────────────────
contract UDPScanVuln {
    event ScanLogged(
        address indexed scanner,
        address indexed target,
        uint16           port,
        UDPScanType      scanType,
        UDPScanAttackType attackType
    );

    /// ❌ no restrictions: log every scan
    function scan(address target, uint16 port) external {
        emit ScanLogged(
            msg.sender,
            target,
            port,
            UDPScanType.PortScan,
            UDPScanAttackType.SweepFlood
        );
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: flood‑scan a range of ports
///
///    • AttackType: SweepFlood
///─────────────────────────────────────────────────────────────────────────────
contract Attack_UDPScan {
    UDPScanVuln public target;

    constructor(UDPScanVuln _t) { target = _t; }

    /// flood‑scan multiple ports
    function floodScan(address dst, uint16[] calldata ports) external {
        for (uint i = 0; i < ports.length; i++) {
            target.scan(dst, ports[i]);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE UDP SCAN WITH ICMP RATE‑LIMIT
///
///    • Defense: RateLimitICMP – cap scans per block per scanner
///─────────────────────────────────────────────────────────────────────────────
contract UDPScanSafeRateLimit {
    event ScanLogged(
        address indexed scanner,
        address indexed target,
        uint16           port,
        UDPScanType      scanType,
        UDPScanDefenseType defense
    );

    mapping(address => uint256) public lastBlock;
    mapping(address => uint16)  public scansInBlock;
    uint16 public constant MAX_PER_BLOCK = 20;

    function scan(address target, uint16 port) external {
        // reset counter each block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            scansInBlock[msg.sender] = 0;
        }
        scansInBlock[msg.sender] += 1;
        if (scansInBlock[msg.sender] > MAX_PER_BLOCK) revert UDP__TooManyScans();

        emit ScanLogged(
            msg.sender,
            target,
            port,
            UDPScanType.PortScan,
            UDPScanDefenseType.RateLimitICMP
        );
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE UDP SCAN WITH UNIFORM RESPONSE
///
///    • Defense: UniformResponse – always log the same “no response” event
///─────────────────────────────────────────────────────────────────────────────
contract UDPScanSafeUniform {
    event ScanResult(
        address indexed scanner,
        address indexed target,
        uint16           port,
        bool             open,
        UDPScanDefenseType defense
    );

    function scan(address target, uint16 port) external {
        // ✅ do not reveal whether port is open or closed
        emit ScanResult(
            msg.sender,
            target,
            port,
            false,
            UDPScanDefenseType.UniformResponse
        );
    }
}
