// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WarmSiteSuite.sol
/// @notice On‐chain analogues of “Warm Site” disaster‐recovery patterns:
///   Types: Standby, Mirrored, OnDemand, Hybrid  
///   AttackTypes: SiteOutage, DataInconsistency, RecoveryDelay, Ransomware  
///   DefenseTypes: Replication, AutomatedFailover, BackupIntegrity, ContinuousMonitoring  

enum WarmSiteType        { Standby, Mirrored, OnDemand, Hybrid }
enum WarmSiteAttackType  { SiteOutage, DataInconsistency, RecoveryDelay, Ransomware }
enum WarmSiteDefenseType { Replication, AutomatedFailover, BackupIntegrity, ContinuousMonitoring }

error WS__NotAvailable();
error WS__RecoveryFailed();
error WS__TooFrequent();
error WS__IntegrityCheckFailed();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE SITE
//
//    • ❌ no replication or failover: outage causes downtime → SiteOutage
////////////////////////////////////////////////////////////////////////////////
contract WarmSiteVuln {
    bool public siteUp;
    event SiteStatus(
        address indexed who,
        bool                up,
        WarmSiteType        stype,
        WarmSiteAttackType  attack
    );

    function toggleSite(bool up, WarmSiteType stype) external {
        siteUp = up;
        emit SiteStatus(msg.sender, up, stype, WarmSiteAttackType.SiteOutage);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates causing an outage
////////////////////////////////////////////////////////////////////////////////
contract Attack_WarmSite {
    WarmSiteVuln public target;

    constructor(WarmSiteVuln _t) {
        target = _t;
    }

    function causeOutage() external {
        target.toggleSite(false, WarmSiteType.Standby);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH REPLICATION
//
//    • ✅ Defense: Replication – keep mirrored copy
////////////////////////////////////////////////////////////////////////////////
contract WarmSiteSafeReplication {
    bool public primaryUp;
    bool public mirrorUp;
    event SiteStatus(
        address indexed who,
        bool                   up,
        WarmSiteType           stype,
        WarmSiteDefenseType    defense
    );

    function togglePrimary(bool up) external {
        primaryUp = up;
        if (!up) {
            // mirror takes over
            mirrorUp = true;
        }
        emit SiteStatus(msg.sender, up, WarmSiteType.Mirrored, WarmSiteDefenseType.Replication);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH AUTOMATED FAILOVER
//
//    • ✅ Defense: AutomatedFailover – detect outage and switch
////////////////////////////////////////////////////////////////////////////////
contract WarmSiteSafeFailover {
    bool public primaryUp;
    bool public usingMirror;
    event Failover(
        address indexed who,
        WarmSiteType          from,
        WarmSiteType          to,
        WarmSiteDefenseType   defense
    );

    error WS__RecoveryFailed();

    function detectAndFailover() external {
        if (primaryUp) revert WS__RecoveryFailed();
        usingMirror = true;
        emit Failover(msg.sender, WarmSiteType.Standby, WarmSiteType.Mirrored, WarmSiteDefenseType.AutomatedFailover);
    }

    function recoverPrimary() external {
        primaryUp = true;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH BACKUP INTEGRITY & MONITORING
//
//    • ✅ Defense: BackupIntegrity – verify backups periodically  
//               ContinuousMonitoring – alert on anomalies
////////////////////////////////////////////////////////////////////////////////
contract WarmSiteSafeAdvanced {
    mapping(uint256 => bytes32) public backups;      // timestamp → hash
    mapping(address => uint256) public lastCheck;
    event BackupVerified(
        address indexed who,
        uint256           timestamp,
        WarmSiteDefenseType defense
    );
    event Alert(
        address indexed who,
        string            reason,
        WarmSiteDefenseType defense
    );

    uint256 public constant MIN_INTERVAL = 1 days;

    error WS__TooFrequent();
    error WS__IntegrityCheckFailed();

    function storeBackup(uint256 timestamp, bytes32 hash) external {
        backups[timestamp] = hash;
    }

    function verifyBackup(uint256 timestamp, bytes calldata data) external {
        if (block.timestamp < lastCheck[msg.sender] + MIN_INTERVAL) revert WS__TooFrequent();
        lastCheck[msg.sender] = block.timestamp;
        if (keccak256(data) != backups[timestamp]) {
            emit Alert(msg.sender, "backup integrity failure", WarmSiteDefenseType.BackupIntegrity);
            revert WS__IntegrityCheckFailed();
        }
        emit BackupVerified(msg.sender, timestamp, WarmSiteDefenseType.BackupIntegrity);
    }

    function monitor() external {
        // stub monitoring
        emit Alert(msg.sender, "monitoring: site healthy", WarmSiteDefenseType.ContinuousMonitoring);
    }
}
