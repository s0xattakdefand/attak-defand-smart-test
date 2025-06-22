// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AccessControlSuite.sol
/// @notice On‑chain analogues of “Access Control” patterns:
///   Types: Discretionary, Mandatory, RoleBased, AttributeBased  
///   AttackTypes: Spoofing, PrivilegeEscalation, Bypass, Tampering  
///   DefenseTypes: ACL, RBAC, ABAC, PolicyEnforcement  

enum AccessControlType        { Discretionary, Mandatory, RoleBased, AttributeBased }
enum AccessControlAttackType  { Spoofing, PrivilegeEscalation, Bypass, Tampering }
enum AccessControlDefenseType { ACL, RBAC, ABAC, PolicyEnforcement }

error AC__NotOwner();
error AC__Unauthorized();
error AC__NoRole();
error AC__InsufficientLevel();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE RESOURCE (no access control)
//    • any caller may store or read → Bypass
////////////////////////////////////////////////////////////////////////////////
contract AccessControlVuln {
    mapping(uint256 => bytes) public dataStore;
    event DataWritten(
        address indexed who,
        uint256 indexed id,
        AccessControlType        atype,
        AccessControlAttackType  attack
    );
    event DataRead(
        address indexed who,
        uint256 indexed id,
        bytes                   data,
        AccessControlAttackType  attack
    );

    function write(uint256 id, bytes calldata data) external {
        dataStore[id] = data;
        emit DataWritten(msg.sender, id, AccessControlType.Discretionary, AccessControlAttackType.Bypass);
    }

    function read(uint256 id) external {
        bytes memory d = dataStore[id];
        emit DataRead(msg.sender, id, d, AccessControlAttackType.Bypass);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • demonstrates spoofing and privilege escalation
////////////////////////////////////////////////////////////////////////////////
contract Attack_AccessControl {
    AccessControlVuln public target;
    constructor(AccessControlVuln _t) { target = _t; }

    function escalate(uint256 id, bytes calldata fakeData) external {
        // attacker writes unauthorized data
        target.write(id, fakeData);
    }

    function spoofRead(uint256 id) external {
        // attacker reads data bypassing controls
        target.read(id);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACL (Discretionary + ACL)
//    • Defense: only owner or whitelisted may write/read
////////////////////////////////////////////////////////////////////////////////
contract AccessControlSafeACL {
    mapping(uint256 => bytes)               private dataStore;
    mapping(uint256 => mapping(address => bool)) public acl;
    address public owner;

    event DataWritten(
        address indexed who,
        uint256 indexed id,
        AccessControlDefenseType defense
    );
    event DataRead(
        address indexed who,
        uint256 indexed id,
        bytes                   data,
        AccessControlDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function setACL(uint256 id, address who, bool ok) external {
        if (msg.sender != owner) revert AC__NotOwner();
        acl[id][who] = ok;
    }

    function write(uint256 id, bytes calldata data) external {
        if (!acl[id][msg.sender]) revert AC__Unauthorized();
        dataStore[id] = data;
        emit DataWritten(msg.sender, id, AccessControlDefenseType.ACL);
    }

    function read(uint256 id) external {
        if (!acl[id][msg.sender]) revert AC__Unauthorized();
        bytes memory d = dataStore[id];
        emit DataRead(msg.sender, id, d, AccessControlDefenseType.ACL);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH RBAC (RoleBased)
//    • Defense: assign roles to users and roles to resources
////////////////////////////////////////////////////////////////////////////////
contract AccessControlSafeRBAC {
    mapping(bytes32 => mapping(address => bool)) public roles;       // role → user → allowed
    mapping(uint256 => bytes32)           public resourceRole;      // resource → required role

    event RoleAssigned(
        bytes32 indexed role,
        address indexed who,
        AccessControlDefenseType defense
    );
    event ResourceRoleSet(
        uint256 indexed id,
        bytes32          role,
        AccessControlDefenseType defense
    );
    event DataAccessed(
        address indexed who,
        uint256 indexed id,
        bytes                   data,
        AccessControlDefenseType defense
    );

    mapping(uint256 => bytes) private dataStore;

    function assignRole(bytes32 role, address who, bool ok) external {
        // in a real system, restrict to admin; omitted for brevity
        roles[role][who] = ok;
        emit RoleAssigned(role, who, AccessControlDefenseType.RBAC);
    }

    function setResourceRole(uint256 id, bytes32 role) external {
        // restricted to resource owner/admin in practice
        resourceRole[id] = role;
        emit ResourceRoleSet(id, role, AccessControlDefenseType.RBAC);
    }

    function write(uint256 id, bytes calldata data) external {
        bytes32 role = resourceRole[id];
        if (!roles[role][msg.sender]) revert AC__NoRole();
        dataStore[id] = data;
        emit DataAccessed(msg.sender, id, data, AccessControlDefenseType.RBAC);
    }

    function read(uint256 id) external {
        bytes32 role = resourceRole[id];
        if (!roles[role][msg.sender]) revert AC__NoRole();
        bytes memory d = dataStore[id];
        emit DataAccessed(msg.sender, id, d, AccessControlDefenseType.RBAC);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE WITH ABAC (AttributeBased)
//    • Defense: require user attribute level ≥ resource threshold
////////////////////////////////////////////////////////////////////////////////
contract AccessControlSafeABAC {
    mapping(address => uint256) public clearanceLevel;      // user → level
    mapping(uint256 => uint256) public requiredLevel;      // resource → minimum level

    event DataWritten(
        address indexed who,
        uint256 indexed id,
        AccessControlDefenseType defense
    );
    event DataRead(
        address indexed who,
        uint256 indexed id,
        bytes                   data,
        AccessControlDefenseType defense
    );

    mapping(uint256 => bytes) private dataStore;

    function setClearance(address who, uint256 level) external {
        // in practice restricted to admin
        clearanceLevel[who] = level;
    }

    function setRequiredLevel(uint256 id, uint256 level) external {
        // in practice restricted to resource owner
        requiredLevel[id] = level;
    }

    function write(uint256 id, bytes calldata data) external {
        if (clearanceLevel[msg.sender] < requiredLevel[id]) revert AC__InsufficientLevel();
        dataStore[id] = data;
        emit DataWritten(msg.sender, id, AccessControlDefenseType.ABAC);
    }

    function read(uint256 id) external {
        if (clearanceLevel[msg.sender] < requiredLevel[id]) revert AC__InsufficientLevel();
        bytes memory d = dataStore[id];
        emit DataRead(msg.sender, id, d, AccessControlDefenseType.ABAC);
    }
}
