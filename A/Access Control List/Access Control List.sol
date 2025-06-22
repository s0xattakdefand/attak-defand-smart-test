// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AccessControlListSuite.sol
/// @notice On‑chain analogues of “Access Control List” (ACL) patterns:
///   Types: Standard, Extended, DefaultDeny, DefaultAllow  
///   AttackTypes: Spoofing, Bypass, PrivilegeEscalation, Tampering  
///   DefenseTypes: ACLCheck, StatefulInspection, Logging, Immutable  

enum AccessControlListType        { Standard, Extended, DefaultDeny, DefaultAllow }
enum AccessControlListAttackType  { Spoofing, Bypass, PrivilegeEscalation, Tampering }
enum AccessControlListDefenseType { ACLCheck, StatefulInspection, Logging, Immutable }

error ACL__NotOwner();
error ACL__Unauthorized();
error ACL__Tampered();
error ACL__TooFrequent();
error ACL__Immutable();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE ACL SERVICE
///
///    • no owner or checks: anyone may grant or revoke any address  
///    • Attack: Tampering, Spoofing  
///─────────────────────────────────────────────────────────────────────────────
contract ACLVuln {
    mapping(uint256 => mapping(address => bool)) public acl;
    event AccessAttempt(
        address indexed who,
        uint256 indexed resource,
        bool granted,
        AccessControlListAttackType attack
    );

    /// ❌ no owner check: any caller can grant or revoke
    function setPermission(uint256 resource, address user, bool ok) external {
        acl[resource][user] = ok;
    }

    /// ❌ no check: anyone may attempt access
    function access(uint256 resource) external {
        bool ok = acl[resource][msg.sender];
        emit AccessAttempt(msg.sender, resource, ok, AccessControlListAttackType.Bypass);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • demonstrates spoofing and mass tampering  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_ACL {
    ACLVuln public target;
    constructor(ACLVuln _t) { target = _t; }

    /// spoof by granting self permissions
    function spoofGrant(uint256 resource) external {
        target.setPermission(resource, msg.sender, true);
    }

    /// tamper ACL for many users
    function massTamper(uint256 resource, address[] calldata users) external {
        for (uint i = 0; i < users.length; i++) {
            target.setPermission(resource, users[i], true);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE ACL (OWNER‑ONLY & ACL CHECK)
///
///    • Defense: only owner may set, ACLCheck on access  
///─────────────────────────────────────────────────────────────────────────────
contract ACLSafe {
    mapping(uint256 => mapping(address => bool)) private _acl;
    address public owner;
    event AccessAttempt(
        address indexed who,
        uint256 indexed resource,
        bool granted,
        AccessControlListDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function setPermission(uint256 resource, address user, bool ok) external {
        if (msg.sender != owner) revert ACL__NotOwner();
        _acl[resource][user] = ok;
    }

    function access(uint256 resource) external {
        bool ok = _acl[resource][msg.sender];
        if (!ok) revert ACL__Unauthorized();
        emit AccessAttempt(msg.sender, resource, true, AccessControlListDefenseType.ACLCheck);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE STATEFUL ACL (RATE‑LIMIT & LOGGING)
///
///    • Defense: StatefulInspection – track and limit accesses  
///               Logging – emit all attempts  
///─────────────────────────────────────────────────────────────────────────────
contract ACLSafeStateful {
    mapping(uint256 => mapping(address => bool)) public acl;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    address public owner;
    uint256 public constant MAX_PER_BLOCK = 5;

    event AccessAttempt(
        address indexed who,
        uint256 indexed resource,
        bool granted,
        AccessControlListDefenseType defense
    );

    error ACL__TooFrequent();

    constructor() {
        owner = msg.sender;
    }

    function setPermission(uint256 resource, address user, bool ok) external {
        if (msg.sender != owner) revert ACL__NotOwner();
        acl[resource][user] = ok;
    }

    function access(uint256 resource) external {
        // rate‑limit per caller
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert ACL__TooFrequent();

        bool ok = acl[resource][msg.sender];
        if (!ok) revert ACL__Unauthorized();
        emit AccessAttempt(msg.sender, resource, true, AccessControlListDefenseType.StatefulInspection);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) IMMUTABLE ACL (ONE‑TIME SET & DEFAULT‑DENY)
///
///    • Defense: Immutable – once set, cannot be changed  
///               DefaultDeny – unknown users denied by default  
///─────────────────────────────────────────────────────────────────────────────
contract ACLSafeImmutable {
    mapping(uint256 => mapping(address => bool)) public acl;
    mapping(uint256 => mapping(address => bool)) private _locked;
    address public owner;
    event AccessAttempt(
        address indexed who,
        uint256 indexed resource,
        bool granted,
        AccessControlListDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    /// set permission only once per (resource,user)
    function setPermission(uint256 resource, address user, bool ok) external {
        if (msg.sender != owner) revert ACL__NotOwner();
        if (_locked[resource][user]) revert ACL__Immutable();
        acl[resource][user] = ok;
        _locked[resource][user] = true;
    }

    /// default‑deny: only explicitly allowed may access
    function access(uint256 resource) external {
        bool ok = acl[resource][msg.sender];
        if (!ok) revert ACL__Unauthorized();
        emit AccessAttempt(msg.sender, resource, true, AccessControlListDefenseType.Immutable);
    }
}
