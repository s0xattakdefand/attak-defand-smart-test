// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DistributedScansSuite.sol
/// @notice On‑chain analogues of “Distributed Scans” patterns:
///   Types: Horizontal, Vertical, Stealth  
///   AttackTypes: ResourceExhaustion, DetectionEvasion, IPSpoofing  
///   DefenseTypes: RateLimit, HoneypotDetection, AccessControl  

enum DistributedScanType           { Horizontal, Vertical, Stealth }
enum DistributedScanAttackType     { ResourceExhaustion, DetectionEvasion, IPSpoofing }
enum DistributedScanDefenseType    { RateLimit, HoneypotDetection, AccessControl }

error DSN__TooManyScans();
error DSN__NotAllowed();
error DSN__FalsePositive();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE: no limits or checks on scanning
///
///    • any caller may scan any target at any rate  
///    • Attack: ResourceExhaustion
///─────────────────────────────────────────────────────────────────────────────
contract DistributedScansVuln {
    event ScanPerformed(
        address indexed by,
        address indexed target,
        DistributedScanType dtype,
        DistributedScanAttackType attack
    );

    function scan(address target, DistributedScanType dtype) external {
        emit ScanPerformed(msg.sender, target, dtype, DistributedScanAttackType.ResourceExhaustion);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: flood scans and spoofing
///
///    • Attack: ResourceExhaustion, IPSpoofing
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DistributedScans {
    DistributedScansVuln public target;
    constructor(DistributedScansVuln _t) { target = _t; }

    /// flood many scans to exhaust resources
    function floodScan(address to, DistributedScanType dtype, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            target.scan(to, dtype);
        }
    }

    /// stub for IP spoofing scan (emits same event)
    function spoofedScan(address to, DistributedScanType dtype) external {
        target.scan(to, dtype);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE: rate‑limit per block per caller
///
///    • Defense: RateLimit  
///─────────────────────────────────────────────────────────────────────────────
contract DistributedScansSafeRateLimit {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;

    event ScanPerformed(
        address indexed by,
        address indexed target,
        DistributedScanType dtype,
        DistributedScanDefenseType defense
    );

    function scan(address target, DistributedScanType dtype) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DSN__TooManyScans();

        emit ScanPerformed(msg.sender, target, dtype, DistributedScanDefenseType.RateLimit);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE: honeypot detection on repetitive scans
///
///    • Defense: HoneypotDetection  
///─────────────────────────────────────────────────────────────────────────────
contract DistributedScansSafeHoneypot {
    mapping(address => uint256) public scanCount;

    event ScanPerformed(
        address indexed by,
        address indexed target,
        DistributedScanType dtype,
        DistributedScanDefenseType defense
    );
    event HoneypotAlert(
        address indexed by,
        address indexed target
    );

    function scan(address target, DistributedScanType dtype) external {
        scanCount[target]++;
        // every 10th scan triggers honeypot detection
        if (scanCount[target] % 10 == 0) {
            emit HoneypotAlert(msg.sender, target);
            revert DSN__FalsePositive();
        }
        emit ScanPerformed(msg.sender, target, dtype, DistributedScanDefenseType.HoneypotDetection);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE: access control for authorized scanners only
///
///    • Defense: AccessControl  
///─────────────────────────────────────────────────────────────────────────────
contract DistributedScansSafeAuth {
    mapping(address => bool) public allowed;
    address public owner;

    event ScanPerformed(
        address indexed by,
        address indexed target,
        DistributedScanType dtype,
        DistributedScanDefenseType defense
    );

    error DSN__NotAllowed();

    constructor() {
        owner = msg.sender;
    }

    function setAllowed(address who, bool ok) external {
        require(msg.sender == owner, "only owner");
        allowed[who] = ok;
    }

    function scan(address target, DistributedScanType dtype) external {
        if (!allowed[msg.sender]) revert DSN__NotAllowed();
        emit ScanPerformed(msg.sender, target, dtype, DistributedScanDefenseType.AccessControl);
    }
}
