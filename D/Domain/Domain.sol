// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DomainSuite.sol
/// @notice On‑chain analogues of “Domain” security patterns:
///   Types: Administrative, Security, Trust  
///   AttackTypes: Hijacking, CrossDomain, Escalation  
///   DefenseTypes: Isolation, Validation, AccessControl  

enum DomainType           { Administrative, Security, Trust }
enum DomainAttackType     { Hijacking, CrossDomain, Escalation }
enum DomainDefenseType    { Isolation, Validation, AccessControl }

error DM__NotOwner();
error DM__InvalidDomain();
error DM__NotMember();
error DM__TooManyCross();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DOMAIN MANAGER
//
//    • no access control: anyone may join or switch any domain  
//    • Attack: Hijacking, CrossDomain
////////////////////////////////////////////////////////////////////////////////
contract DomainVuln {
    mapping(address => DomainType) public domainOf;
    event DomainChanged(address indexed who, DomainType dtype, DomainAttackType attack);

    /// ❌ anyone may set their own or others’ domain
    function setDomain(address who, DomainType dtype) external {
        domainOf[who] = dtype;
        emit DomainChanged(who, dtype, DomainAttackType.Hijacking);
    }

    /// ❌ cross‑domain call with no checks
    function crossDomainCall(address target, DomainType dtype) external {
        domainOf[target] = dtype;
        emit DomainChanged(target, dtype, DomainAttackType.CrossDomain);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • demonstrates hijacking and cross‑domain escalation
////////////////////////////////////////////////////////////////////////////////
contract Attack_Domain {
    DomainVuln public target;
    constructor(DomainVuln _t) { target = _t; }

    /// hijack another’s domain
    function hijack(address victim, DomainType dtype) external {
        target.setDomain(victim, dtype);
    }

    /// force a cross‑domain escalation
    function escalate(address svc) external {
        target.crossDomainCall(svc, DomainType.Trust);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE DOMAIN ISOLATION
//
//    • Defense: Isolation – only members of a domain may act within it
////////////////////////////////////////////////////////////////////////////////
contract DomainSafeIsolation {
    mapping(address => DomainType) public domainOf;
    mapping(DomainType => mapping(address => bool)) public members;
    address public owner;
    event Accessed(address indexed who, DomainType dtype, DomainDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    /// owner assigns domain membership
    function assign(address who, DomainType dtype) external {
        if (msg.sender != owner) revert DM__NotOwner();
        domainOf[who] = dtype;
        members[dtype][who] = true;
    }

    /// only members may access their domain
    function accessDomain(DomainType dtype) external {
        if (!members[dtype][msg.sender]) revert DM__NotMember();
        emit Accessed(msg.sender, dtype, DomainDefenseType.Isolation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE DOMAIN VALIDATION
//
//    • Defense: Validation – require claimed domain matches recorded assignment
////////////////////////////////////////////////////////////////////////////////
contract DomainSafeValidation {
    mapping(address => DomainType) public domainOf;
    address public owner;
    event Accessed(address indexed who, DomainType dtype, DomainDefenseType defense);

    error DM__DomainMismatch();

    constructor() {
        owner = msg.sender;
    }

    /// owner records legitimate domain
    function record(address who, DomainType dtype) external {
        if (msg.sender != owner) revert DM__NotOwner();
        domainOf[who] = dtype;
    }

    /// require caller’s declared domain matches record
    function validateAccess(DomainType dtype) external {
        if (domainOf[msg.sender] != dtype) revert DM__DomainMismatch();
        emit Accessed(msg.sender, dtype, DomainDefenseType.Validation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE CROSS‑DOMAIN CONTROL WITH RATE‑LIMITED AUTH
//
//    • Defense: AccessControl – only owner may cross domains  
//               plus rate‑limit to prevent flooding
////////////////////////////////////////////////////////////////////////////////
contract DomainSafeCross {
    DomainVuln public legacy;
    address public owner;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_CROSS_PER_BLOCK = 3;
    event Crossed(address indexed by, address indexed target, DomainType dtype, DomainDefenseType defense);

    error DM__TooMany();
    error DM__NotOwner();

    constructor(DomainVuln _legacy) {
        legacy = _legacy;
        owner = msg.sender;
    }

    /// only owner may invoke cross‑domain changes, rate‑limited
    function crossDomainChange(address target, DomainType dtype) external {
        if (msg.sender != owner) revert DM__NotOwner();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_CROSS_PER_BLOCK) revert DM__TooMany();

        legacy.setDomain(target, dtype);
        emit Crossed(msg.sender, target, dtype, DomainDefenseType.AccessControl);
    }
}
