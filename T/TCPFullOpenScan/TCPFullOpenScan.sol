// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TCPFullOpenScanSuite.sol
/// @notice On‑chain analogues of “TCP Full Open Scan” with common pitfalls
///   • Types: ScanType, ScanAttackType, ScanDefenseType  
///   • Attack: ConnectScan  
///   • Defense: AccessControl, RateLimit  

enum TCPScanType       { FullOpen }
enum TCPScanAttackType { ConnectScan }
enum TCPScanDefenseType{ AccessControl, RateLimit }

error TCPScan__NotAllowed();
error TCPScan__TooManyScans();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE TCP FULL OPEN SCAN
//
//   • Type: FullOpen
//   • Attack: ConnectScan
//   • Defense: —
//
////////////////////////////////////////////////////////////////////////
contract TCPFullOpenScanVuln {
    event Scanned(
        address indexed scanner,
        address indexed target,
        uint16           port,
        TCPScanType      scanType,
        TCPScanAttackType attackType
    );

    /// anyone may scan any port; always “open”
    function scan(address target, uint16 port) external returns (bool open) {
        emit Scanned(msg.sender, target, port, TCPScanType.FullOpen, TCPScanAttackType.ConnectScan);
        return true;
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//   Uses the vulnerable scan to flood‑scan a list of ports.
//
//   AttackType: ConnectScan
//
////////////////////////////////////////////////////////////////////////
contract Attack_TCPFullOpenScan {
    TCPFullOpenScanVuln public target;
    event AttackExecuted(TCPScanAttackType attackType, uint16 port);

    constructor(TCPFullOpenScanVuln _t) { target = _t; }

    /// attacker scans multiple ports
    function floodScan(address dst, uint16[] calldata ports) external {
        for (uint i = 0; i < ports.length; i++) {
            target.scan(dst, ports[i]);
            emit AttackExecuted(TCPScanAttackType.ConnectScan, ports[i]);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE TCP FULL OPEN SCAN
//
//   • Defense: AccessControl + RateLimit
//
////////////////////////////////////////////////////////////////////////
contract TCPFullOpenScanSafe {
    address public owner;
    mapping(address => bool) public allowedScanners;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public scansInBlock;

    uint256 public constant MAX_SCAN_PER_BLOCK = 10;
    event Scanned(
        address indexed scanner,
        address indexed target,
        uint16           port,
        TCPScanType      scanType,
        TCPScanDefenseType defenseType
    );

    constructor() {
        owner = msg.sender;
    }

    /// only owner may whitelist scanners
    function setAllowedScanner(address who, bool ok) external {
        require(msg.sender == owner, "TCPScanSafe: only owner");
        allowedScanners[who] = ok;
    }

    /// rate‑limited, whitelist‑only scan
    function scan(address targetAddr, uint16 port) external returns (bool open) {
        if (!allowedScanners[msg.sender]) revert TCPScan__NotAllowed();

        // reset per‑block counter
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            scansInBlock[msg.sender] = 0;
        }
        scansInBlock[msg.sender] += 1;
        if (scansInBlock[msg.sender] > MAX_SCAN_PER_BLOCK) revert TCPScan__TooManyScans();

        emit Scanned(
            msg.sender,
            targetAddr,
            port,
            TCPScanType.FullOpen,
            TCPScanDefenseType.RateLimit
        );
        return true;
    }
}
