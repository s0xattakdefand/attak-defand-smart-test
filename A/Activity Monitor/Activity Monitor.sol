// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ActivityMonitorSuite.sol
/// @notice On-chain analogues of “Activity Monitor” patterns:
///   Types: UserActivity, NetworkActivity, SystemActivity  
///   AttackTypes: Evasion, Flooding, Spoofing, Tampering  
///   DefenseTypes: ImmutableLogs, AnomalyDetection, RateLimit, Whitelisting  

enum ActivityMonitorType        { UserActivity, NetworkActivity, SystemActivity }
enum ActivityMonitorAttackType  { Evasion, Flooding, Spoofing, Tampering }
enum ActivityMonitorDefenseType { ImmutableLogs, AnomalyDetection, RateLimit, Whitelisting }

error AM__NotAllowed();
error AM__TooFrequent();
error AM__Suspicious();
error AM__NotWhitelisted();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE MONITOR (no integrity, no limits)
//    • logs can be overwritten or flooded without checks
////////////////////////////////////////////////////////////////////////////////
contract ActivityMonitorVuln {
    mapping(address => string[]) public logs;
    event ActivityDetected(
        address indexed who,
        ActivityMonitorType  atype,
        string               info,
        ActivityMonitorAttackType attack
    );

    /// ❌ no integrity or rate‐limit
    function logActivity(ActivityMonitorType atype, string calldata info) external {
        logs[msg.sender].push(info);
        emit ActivityDetected(msg.sender, atype, info, ActivityMonitorAttackType.Flooding);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • demonstrates log flooding and tampering
////////////////////////////////////////////////////////////////////////////////
contract Attack_ActivityMonitor {
    ActivityMonitorVuln public target;
    constructor(ActivityMonitorVuln _t) { target = _t; }

    /// flood logs with repeated entries
    function flood(ActivityMonitorType atype, string calldata info, uint256 times) external {
        for (uint i = 0; i < times; i++) {
            target.logActivity(atype, info);
        }
    }

    /// tamper by logging misleading info
    function spoof(ActivityMonitorType atype, string calldata fakeInfo) external {
        target.logActivity(atype, fakeInfo);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH IMMUTABLE LOGS
//    • Defense: ImmutableLogs – append‐only, cannot delete or overwrite
////////////////////////////////////////////////////////////////////////////////
contract ActivityMonitorSafeImmutable {
    mapping(address => string[]) private _logs;
    event ActivityDetected(
        address indexed who,
        ActivityMonitorType  atype,
        string               info,
        ActivityMonitorDefenseType defense
    );

    /// ✅ append‐only logs
    function logActivity(ActivityMonitorType atype, string calldata info) external {
        _logs[msg.sender].push(info);
        emit ActivityDetected(msg.sender, atype, info, ActivityMonitorDefenseType.ImmutableLogs);
    }

    function getLogs(address who) external view returns (string[] memory) {
        return _logs[who];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ANOMALY DETECTION
//    • Defense: AnomalyDetection – flag too many similar events
////////////////////////////////////////////////////////////////////////////////
contract ActivityMonitorSafeAnomaly {
    mapping(address => mapping(uint256 => uint256)) public counts; // who → block → count
    event ActivityDetected(
        address indexed who,
        ActivityMonitorType  atype,
        string               info,
        ActivityMonitorDefenseType defense
    );
    event AnomalyAlert(
        address indexed who,
        ActivityMonitorType  atype,
        string               reason,
        ActivityMonitorDefenseType defense
    );

    error AM__Suspicious();

    /// ✅ detect flooding within same block
    function logActivity(ActivityMonitorType atype, string calldata info) external {
        uint256 b = block.number;
        counts[msg.sender][b] += 1;
        if (counts[msg.sender][b] > 10) {
            emit AnomalyAlert(msg.sender, atype, "excessive events in block", ActivityMonitorDefenseType.AnomalyDetection);
            revert AM__Suspicious();
        }
        emit ActivityDetected(msg.sender, atype, info, ActivityMonitorDefenseType.AnomalyDetection);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE WITH WHITELISTING & RATE-LIMIT
//    • Defense: Whitelisting – only approved can log
//               RateLimit – cap events per block
////////////////////////////////////////////////////////////////////////////////
contract ActivityMonitorSafeAuth {
    mapping(address => bool) public whitelist;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    address public owner;
    uint256 public constant MAX_PER_BLOCK = 5;

    event ActivityDetected(
        address indexed who,
        ActivityMonitorType  atype,
        string               info,
        ActivityMonitorDefenseType defense
    );

    error AM__NotWhitelisted();
    error AM__TooFrequent();

    constructor() {
        owner = msg.sender;
        whitelist[msg.sender] = true;
    }

    function setWhitelisted(address who, bool ok) external {
        require(msg.sender == owner, "only owner");
        whitelist[who] = ok;
    }

    /// ✅ enforce whitelist and rate-limit
    function logActivity(ActivityMonitorType atype, string calldata info) external {
        if (!whitelist[msg.sender]) revert AM__NotWhitelisted();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert AM__TooFrequent();

        emit ActivityDetected(msg.sender, atype, info, ActivityMonitorDefenseType.RateLimit);
    }
}
