// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataOwnerSuite.sol
/// @notice On‑chain analogues of “Data Owner” patterns:
///   Types: Primary, Delegate, Backup  
///   AttackTypes: UnauthorizedAccess, OwnershipHijack, RevocationBypass  
///   DefenseTypes: AccessControl, ImmutableOwnership, RevocableOwnership  

enum DataOwnerType         { Primary, Delegate, Backup }
enum DataOwnerAttackType   { UnauthorizedAccess, OwnershipHijack, RevocationBypass }
enum DataOwnerDefenseType  { AccessControl, ImmutableOwnership, RevocableOwnership }

error DO__NotOwner();
error DO__AlreadySet();
error DO__AccessDenied();
error DO__NoDelegation();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE OWNER REGISTRY
///
///    • anyone may register or change ownership of any data ID  
///    • Attack: OwnershipHijack  
///─────────────────────────────────────────────────────────────────────────────
contract DataOwnerVuln {
    mapping(uint256 => address) public ownerOf;
    event OwnerChanged(
        uint256 indexed dataId,
        address indexed newOwner,
        DataOwnerAttackType attack
    );

    /// ❌ no access control
    function setOwner(uint256 dataId, address newOwner) external {
        ownerOf[dataId] = newOwner;
        emit OwnerChanged(dataId, newOwner, DataOwnerAttackType.OwnershipHijack);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • demonstrates hijacking ownership and unauthorized access  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DataOwner {
    DataOwnerVuln public target;
    constructor(DataOwnerVuln _t) { target = _t; }

    /// hijack ownership of a given data ID
    function hijack(uint256 dataId, address victim) external {
        target.setOwner(dataId, msg.sender);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE OWNER REGISTRY (IMMUTABLE ONCE)
///
///    • Defense: AccessControl + ImmutableOwnership  
///    • only the first setOwner by the true deployer succeeds  
///─────────────────────────────────────────────────────────────────────────────
contract DataOwnerSafe {
    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => bool)    private _set;
    address public immutable deployer;

    event OwnerSet(
        uint256 indexed dataId,
        address indexed owner,
        DataOwnerDefenseType defense
    );

    constructor() {
        deployer = msg.sender;
    }

    /// ✅ only deployer may set each dataId’s owner exactly once
    function setOwner(uint256 dataId, address owner) external {
        if (msg.sender != deployer)              revert DO__NotOwner();
        if (_set[dataId])                        revert DO__AlreadySet();
        _set[dataId] = true;
        ownerOf[dataId] = owner;
        emit OwnerSet(dataId, owner, DataOwnerDefenseType.ImmutableOwnership);
    }

    /// helper: check if msg.sender is owner
    function requireOwner(uint256 dataId) internal view {
        if (msg.sender != ownerOf[dataId]) revert DO__AccessDenied();
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE REVOCABLE OWNER REGISTRY WITH DELEGATION
///
///    • Defense: RevocableOwnership  
///    • deployer is master owner, can assign & revoke, delegates can act  
///─────────────────────────────────────────────────────────────────────────────
contract DataOwnerSafeRevocable {
    struct Info { address owner; address delegate; bool exists; }
    mapping(uint256 => Info) public info;
    address public immutable master;
    event OwnerAssigned(
        uint256 indexed dataId,
        address indexed owner,
        DataOwnerDefenseType defense
    );
    event Delegated(
        uint256 indexed dataId,
        address indexed delegate,
        DataOwnerDefenseType defense
    );
    event OwnershipRevoked(
        uint256 indexed dataId,
        DataOwnerDefenseType defense
    );

    error DO__NoSuchData();
    error DO__NotMaster();
    error DO__NotOwnerOrDelegate();

    modifier onlyMaster() {
        if (msg.sender != master) revert DO__NotOwner();
        _;
    }

    constructor() {
        master = msg.sender;
    }

    /// ✅ master assigns initial owner
    function assign(uint256 dataId, address owner) external onlyMaster {
        if (info[dataId].exists) revert DO__AlreadySet();
        info[dataId] = Info({ owner: owner, delegate: address(0), exists: true });
        emit OwnerAssigned(dataId, owner, DataOwnerDefenseType.RevocableOwnership);
    }

    /// ✅ owner may delegate to a trusted address
    function delegate(uint256 dataId, address who) external {
        Info storage inf = info[dataId];
        if (!inf.exists) revert DO__NoSuchData();
        if (msg.sender != inf.owner) revert DO__NotOwner();
        inf.delegate = who;
        emit Delegated(dataId, who, DataOwnerDefenseType.RevocableOwnership);
    }

    /// ✅ master or owner can revoke ownership (reset record)
    function revoke(uint256 dataId) external {
        if (msg.sender != master && msg.sender != info[dataId].owner) revert DO__AccessDenied();
        delete info[dataId];
        emit OwnershipRevoked(dataId, DataOwnerDefenseType.RevocableOwnership);
    }

    /// helper: only owner or delegated may perform actions
    function requireAuthorized(uint256 dataId) public view {
        Info storage inf = info[dataId];
        if (!inf.exists)         revert DO__NoSuchData();
        if (msg.sender != inf.owner && msg.sender != inf.delegate) revert DO__NotOwnerOrDelegate();
    }
}
