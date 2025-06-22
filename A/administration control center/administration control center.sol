// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AdministrationControlCenterSuite.sol
/// @notice On-chain analogues of “Administration Control Center” patterns:
///   Types: Centralized, Distributed, RoleBased, PolicyDriven  
///   AttackTypes: UnauthorizedAccess, Misconfiguration, PrivilegeEscalation, Replay  
///   DefenseTypes: AccessControl, AuditLogging, RoleValidation, ChangeManagement  

enum AdministrationControlCenterType       { Centralized, Distributed, RoleBased, PolicyDriven }
enum AdministrationControlCenterAttackType { UnauthorizedAccess, Misconfiguration, PrivilegeEscalation, Replay }
enum AdministrationControlCenterDefenseType{ AccessControl, AuditLogging, RoleValidation, ChangeManagement }

error ACC__NotAdmin();
error ACC__Unauthorized();
error ACC__TooFrequent();
error ACC__InvalidRole();
error ACC__AlreadyConfigured();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE ACC (no controls)
//    • any caller may configure or invoke admin actions → UnauthorizedAccess
////////////////////////////////////////////////////////////////////////////////
contract ACCVuln {
    mapping(string => string) public config;
    event ConfigChanged(
        address indexed who,
        string           key,
        string           value,
        AdministrationControlCenterAttackType attack
    );

    function setConfig(string calldata key, string calldata value) external {
        config[key] = value;
        emit ConfigChanged(msg.sender, key, value, AdministrationControlCenterAttackType.UnauthorizedAccess);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • demonstrates misconfiguration and replay of settings
////////////////////////////////////////////////////////////////////////////////
contract Attack_ACC {
    ACCVuln public target;
    string public lastKey;
    string public lastValue;

    constructor(ACCVuln _t) { target = _t; }

    function hijack(string calldata key, string calldata value) external {
        target.setConfig(key, value);
    }

    function capture(string calldata key, string calldata value) external {
        lastKey = key;
        lastValue = value;
    }

    function replay() external {
        target.setConfig(lastKey, lastValue);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE ACC WITH ACCESS CONTROL
//    • Defense: AccessControl – only owner may configure
////////////////////////////////////////////////////////////////////////////////
contract ACCSafeAccess {
    mapping(string => string) private config;
    address public owner;
    event ConfigChanged(
        address indexed who,
        string           key,
        string           value,
        AdministrationControlCenterDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function setConfig(string calldata key, string calldata value) external {
        if (msg.sender != owner) revert ACC__NotAdmin();
        config[key] = value;
        emit ConfigChanged(msg.sender, key, value, AdministrationControlCenterDefenseType.AccessControl);
    }

    function getConfig(string calldata key) external view returns (string memory) {
        return config[key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE ACC WITH AUDIT LOGGING & RATE-LIMIT
//    • Defense: AuditLogging – log every change  
//               RateLimit – cap changes per block
////////////////////////////////////////////////////////////////////////////////
contract ACCSafeAudit {
    mapping(string => string) public config;
    address public owner;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public changesInBlock;
    uint256 public constant MAX_CHANGES = 3;

    event ConfigChanged(
        address indexed who,
        string           key,
        string           value,
        AdministrationControlCenterDefenseType defense
    );
    event AuditAlert(
        address indexed who,
        string           reason,
        AdministrationControlCenterDefenseType defense
    );

    error ACC__TooFrequent();
    error ACC__NotAdmin();

    constructor() {
        owner = msg.sender;
    }

    function setConfig(string calldata key, string calldata value) external {
        if (msg.sender != owner) revert ACC__NotAdmin();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            changesInBlock[msg.sender] = 0;
        }
        changesInBlock[msg.sender]++;
        if (changesInBlock[msg.sender] > MAX_CHANGES) {
            emit AuditAlert(msg.sender, "rate limit exceeded", AdministrationControlCenterDefenseType.AuditLogging);
            revert ACC__TooFrequent();
        }
        config[key] = value;
        emit ConfigChanged(msg.sender, key, value, AdministrationControlCenterDefenseType.AuditLogging);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED ACC WITH ROLE VALIDATION & CHANGE MANAGEMENT
//    • Defense: RoleValidation – only users with proper role  
//               ChangeManagement – require proposal/approval workflow
////////////////////////////////////////////////////////////////////////////////
contract ACCSafeAdvanced {
    mapping(string => string) public config;
    mapping(address => bytes32) public roles; // user => role
    mapping(uint256 => Proposal) public proposals;
    uint256 public nextPid;
    bytes32 public constant ROLE_ADMIN   = keccak256("ADMIN");
    bytes32 public constant ROLE_MANAGER = keccak256("MANAGER");
    uint256 public threshold = 2;

    struct Proposal {
        string key;
        string value;
        uint256 approvals;
        mapping(address => bool) approved;
        bool executed;
    }

    event ProposalCreated(
        uint256 indexed pid,
        address indexed proposer,
        string           key,
        string           value,
        AdministrationControlCenterDefenseType defense
    );
    event ProposalApproved(
        uint256 indexed pid,
        address indexed approver,
        uint256          approvals,
        AdministrationControlCenterDefenseType defense
    );
    event ConfigChanged(
        uint256 indexed pid,
        address indexed executor,
        string           key,
        string           value,
        AdministrationControlCenterDefenseType defense
    );

    error ACC__Unauthorized();
    error ACC__AlreadyExecuted();

    constructor() {
        roles[msg.sender] = ROLE_ADMIN;
    }

    function assignRole(address user, bytes32 role) external {
        // only admin can assign
        if (roles[msg.sender] != ROLE_ADMIN) revert ACC__Unauthorized();
        roles[user] = role;
    }

    function proposeChange(string calldata key, string calldata value) external {
        bytes32 role = roles[msg.sender];
        if (role != ROLE_ADMIN && role != ROLE_MANAGER) revert ACC__Unauthorized();
        Proposal storage p = proposals[nextPid];
        p.key = key;
        p.value = value;
        emit ProposalCreated(nextPid, msg.sender, key, value, AdministrationControlCenterDefenseType.RoleValidation);
        nextPid++;
    }

    function approveChange(uint256 pid) external {
        Proposal storage p = proposals[pid];
        if (p.executed) revert ACC__AlreadyExecuted();
        bytes32 role = roles[msg.sender];
        if (role != ROLE_ADMIN && role != ROLE_MANAGER) revert ACC__Unauthorized();
        if (!p.approved[msg.sender]) {
            p.approved[msg.sender] = true;
            p.approvals++;
            emit ProposalApproved(pid, msg.sender, p.approvals, AdministrationControlCenterDefenseType.ChangeManagement);
        }
        if (p.approvals >= threshold) {
            p.executed = true;
            config[p.key] = p.value;
            emit ConfigChanged(pid, msg.sender, p.key, p.value, AdministrationControlCenterDefenseType.ChangeManagement);
        }
    }
}
