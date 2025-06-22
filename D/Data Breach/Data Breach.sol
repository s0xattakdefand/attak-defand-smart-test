// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataBreachSuite.sol
/// @notice On‑chain analogues of “Data Breach” reporting patterns:
///   Types: Unintentional, Malicious, Physical, PolicyViolation  
///   AttackTypes: Exfiltration, InsiderThreat, AccidentalExposure, Ransomware  
///   DefenseTypes: EncryptionAtRest, AccessControl, AuditLogging, AnomalyDetection  

enum DataBreachType          { Unintentional, Malicious, Physical, PolicyViolation }
enum DataBreachAttackType    { Exfiltration, InsiderThreat, AccidentalExposure, Ransomware }
enum DataBreachDefenseType   { EncryptionAtRest, AccessControl, AuditLogging, AnomalyDetection }

error DB__NotOwner();
error DB__AlreadyReported();
error DB__TooManyReports();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE BREACH LOGGER
///    • no access control, mutable, logs generic attack
///─────────────────────────────────────────────────────────────────────────────
contract DataBreachVuln {
    mapping(uint256 => DataBreachType) public breaches;
    event BreachReported(
        uint256 indexed id,
        DataBreachType       kind,
        DataBreachAttackType attack
    );

    /// anyone may report or overwrite any breach
    function reportBreach(uint256 id, DataBreachType kind) external {
        breaches[id] = kind;
        emit BreachReported(id, kind, DataBreachAttackType.Exfiltration);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • simulates false or malicious breach reports
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DataBreach {
    DataBreachVuln public target;
    constructor(DataBreachVuln _t) { target = _t; }

    /// attacker spoofs a ransomware breach
    function spoofRansom(uint256 id) external {
        target.reportBreach(id, DataBreachType.Malicious);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE BREACH LOGGER
///    • only owner may report, one‑time per id, logs tailored defense
///─────────────────────────────────────────────────────────────────────────────
contract DataBreachSafe {
    mapping(uint256 => DataBreachType) public breaches;
    mapping(uint256 => bool)        private _reported;
    address public owner;
    event BreachLogged(
        uint256 indexed id,
        DataBreachType       kind,
        DataBreachDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function reportBreach(uint256 id, DataBreachType kind) external {
        if (msg.sender != owner) revert DB__NotOwner();
        if (_reported[id])           revert DB__AlreadyReported();
        _reported[id] = true;
        breaches[id] = kind;
        emit BreachLogged(id, kind, _selectDefense(kind));
    }

    function _selectDefense(DataBreachType kind) internal pure returns (DataBreachDefenseType) {
        if (kind == DataBreachType.Unintentional)    return DataBreachDefenseType.AuditLogging;
        if (kind == DataBreachType.Malicious)        return DataBreachDefenseType.EncryptionAtRest;
        if (kind == DataBreachType.Physical)         return DataBreachDefenseType.AccessControl;
        return DataBreachDefenseType.AnomalyDetection; // PolicyViolation
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) RATE‑LIMITED SAFE LOGGER
///    • only owner, one‑time per id, cap reports per block
///─────────────────────────────────────────────────────────────────────────────
contract DataBreachSafeRateLimit {
    mapping(uint256 => DataBreachType) public breaches;
    mapping(uint256 => bool)        private _reported;
    mapping(address => uint256)     public lastBlock;
    mapping(address => uint256)     public countInBlock;
    address public owner;
    uint256 public constant MAX_PER_BLOCK = 3;
    event BreachLogged(
        uint256 indexed id,
        DataBreachType       kind,
        DataBreachDefenseType defense
    );

    error DB__TooManyReports();

    constructor() {
        owner = msg.sender;
    }

    function reportBreach(uint256 id, DataBreachType kind) external {
        if (msg.sender != owner)            revert DB__NotOwner();
        if (_reported[id])                  revert DB__AlreadyReported();

        // rate‑limit per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DB__TooManyReports();

        _reported[id] = true;
        breaches[id]  = kind;
        emit BreachLogged(id, kind, _selectDefense(kind));
    }

    function _selectDefense(DataBreachType kind) internal pure returns (DataBreachDefenseType) {
        if (kind == DataBreachType.Unintentional)    return DataBreachDefenseType.AuditLogging;
        if (kind == DataBreachType.Malicious)        return DataBreachDefenseType.EncryptionAtRest;
        if (kind == DataBreachType.Physical)         return DataBreachDefenseType.AccessControl;
        return DataBreachDefenseType.AnomalyDetection;
    }
}
