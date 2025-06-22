// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DisasterRecoveryPlanSuite.sol
/// @notice On‑chain analogues of “Disaster Recovery Plan” patterns:
///   Types: BackupPlan, FailoverPlan, ContinuityPlan, ReplicationPlan  
///   AttackTypes: DataLoss, RTOFailure, RPOFailure, SinglePointFail  
///   DefenseTypes: Backup, AutomatedFailover, ContinuityTest, GeoRedundancy  

enum RecoveryPlanType        { BackupPlan, FailoverPlan, ContinuityPlan, ReplicationPlan }
enum RecoveryPlanAttackType  { DataLoss, RTOFailure, RPOFailure, SinglePointFail }
enum RecoveryPlanDefenseType { Backup, AutomatedFailover, ContinuityTest, GeoRedundancy }

error DRP__NotOwner();
error DRP__AlreadyConfigured();
error DRP__FailoverNotReady();
error DRP__TestFailed();
error DRP__NoBackup();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE: No recovery configured
///
///    • no backups, no failover → DataLoss  
///─────────────────────────────────────────────────────────────────────────────
contract DRPVuln {
    mapping(uint256 => bytes) public dataStore;
    event Outage(address indexed who, uint256 id, RecoveryPlanAttackType attack);

    function store(uint256 id, bytes calldata data) external {
        dataStore[id] = data;
    }

    /// simulates a disaster wiping data
    function simulateOutage(uint256 id) external {
        delete dataStore[id];
        emit Outage(msg.sender, id, RecoveryPlanAttackType.DataLoss);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: Exploit lack of recovery
///
///    • DataLoss, RTOFailure  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DRP {
    DRPVuln public target;
    constructor(DRPVuln _t) { target = _t; }

    /// wipe data to cause loss
    function causeDataLoss(uint256 id) external {
        target.simulateOutage(id);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE BACKUP PLAN
///
///    • Defense: Backup – owner may backup & restore  
///─────────────────────────────────────────────────────────────────────────────
contract DRPSafeBackup {
    mapping(uint256 => bytes) private primary;
    mapping(uint256 => bytes) private backup;
    address public owner;
    event BackupCreated(uint256 indexed id, RecoveryPlanDefenseType defense);
    event Restored(uint256 indexed id, RecoveryPlanDefenseType defense);

    constructor() { owner = msg.sender; }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DRP__NotOwner();
        _;
    }

    function createBackup(uint256 id) external onlyOwner {
        backup[id] = primary[id];
        emit BackupCreated(id, RecoveryPlanDefenseType.Backup);
    }

    function restore(uint256 id) external onlyOwner {
        bytes memory data = backup[id];
        if (data.length == 0) revert DRP__NoBackup();
        primary[id] = data;
        emit Restored(id, RecoveryPlanDefenseType.Backup);
    }

    function store(uint256 id, bytes calldata data) external onlyOwner {
        primary[id] = data;
    }

    function retrieve(uint256 id) external view returns (bytes memory) {
        return primary[id];
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE AUTOMATED FAILOVER
///
///    • Defense: AutomatedFailover – configure a secondary that takes over  
///─────────────────────────────────────────────────────────────────────────────
contract DRPSafeFailover {
    mapping(uint256 => bytes) public primary;
    mapping(uint256 => bytes) public secondary;
    mapping(uint256 => bool)  public failedOver;
    address public owner;
    event FailoverConfigured(uint256 indexed id, RecoveryPlanDefenseType defense);
    event FailoverExecuted(uint256 indexed id, RecoveryPlanDefenseType defense);

    constructor() { owner = msg.sender; }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DRP__NotOwner();
        _;
    }

    function configureFailover(uint256 id) external onlyOwner {
        secondary[id] = primary[id];
        emit FailoverConfigured(id, RecoveryPlanDefenseType.AutomatedFailover);
    }

    function triggerFailover(uint256 id) external {
        if (secondary[id].length == 0) revert DRP__FailoverNotReady();
        primary[id] = secondary[id];
        failedOver[id] = true;
        emit FailoverExecuted(id, RecoveryPlanDefenseType.AutomatedFailover);
    }

    function store(uint256 id, bytes calldata data) external onlyOwner {
        primary[id] = data;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE CONTINUITY TEST & GEO‑REDUNDANCY
///
///    • Defense: ContinuityTest – scheduled drills  
///               GeoRedundancy – replicate across regions  
///─────────────────────────────────────────────────────────────────────────────
contract DRPSafeAdvanced {
    mapping(uint256 => bytes) public regionA;
    mapping(uint256 => bytes) public regionB;
    mapping(uint256 => bool)  public lastTestPassed;
    address public owner;
    event ContinuityTest(uint256 indexed id, RecoveryPlanDefenseType defense);
    event GeoReplicated(uint256 indexed id, RecoveryPlanDefenseType defense);

    constructor() { owner = msg.sender; }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DRP__NotOwner();
        _;
    }

    /// simulate a drill: verify both regions have same data
    function runContinuityTest(uint256 id) external onlyOwner {
        if (keccak256(regionA[id]) != keccak256(regionB[id])) revert DRP__TestFailed();
        lastTestPassed[id] = true;
        emit ContinuityTest(id, RecoveryPlanDefenseType.ContinuityTest);
    }

    /// replicate primary to secondary region
    function geoReplicate(uint256 id) external onlyOwner {
        regionB[id] = regionA[id];
        emit GeoReplicated(id, RecoveryPlanDefenseType.GeoRedundancy);
    }

    function storePrimary(uint256 id, bytes calldata data) external onlyOwner {
        regionA[id] = data;
    }
}
