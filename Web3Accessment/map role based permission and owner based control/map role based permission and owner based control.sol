// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title RoleOwnerPermissionSuite.sol
/// @notice On‐chain patterns for mapping Role‐Based and Owner‐Based permissions to prevent broken control:
///   Types: RoleOnly, OwnerOnly, RoleOrOwner, DelegateRole, Composite  
///   AttackTypes: UnauthorizedAccess, PrivilegeEscalation, RoleHijack, OwnerImpersonation  
///   DefenseTypes: RoleCheck, OwnerCheck, CompositeCheck, DelegateCheck, SignatureValidation

enum ROPType              { RoleOnly, OwnerOnly, RoleOrOwner, DelegateRole, Composite }
enum ROPAttackType        { UnauthorizedAccess, PrivilegeEscalation, RoleHijack, OwnerImpersonation }
enum ROPDefenseType       { RoleCheck, OwnerCheck, CompositeCheck, DelegateCheck, SignatureValidation }

error ROP__NotOwner();
error ROP__NoRole();
error ROP__NotAuthorized();
error ROP__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE SERVICE
//    • ❌ no checks ⇒ anyone may call criticalAction → UnauthorizedAccess
////////////////////////////////////////////////////////////////////////////////
contract ROPVuln {
    event CriticalAction(address indexed who, ROPType dtype, ROPAttackType attack);

    function criticalAction(uint256 data, ROPType dtype) external {
        // no permission check
        emit CriticalAction(msg.sender, dtype, ROPAttackType.UnauthorizedAccess);
        // ... critical logic ...
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized calls, role hijack, owner impersonation
////////////////////////////////////////////////////////////////////////////////
contract Attack_ROP {
    ROPVuln public target;
    uint256 public lastData;

    constructor(ROPVuln _t) { target = _t; }

    function bypass(uint256 data) external {
        target.criticalAction(data, ROPType.RoleOnly);
        lastData = data;
    }
    function replay() external {
        target.criticalAction(lastData, ROPType.OwnerOnly);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH OWNER‐ONLY CHECK
//    • ✅ Defense: only owner can call → OwnerCheck
////////////////////////////////////////////////////////////////////////////////
contract ROPSafeOwner {
    address public owner;
    event CriticalAction(address indexed who, ROPType dtype, ROPDefenseType defense);

    constructor() { owner = msg.sender; }

    modifier onlyOwner() {
        if (msg.sender != owner) revert ROP__NotOwner();
        _;
    }

    function criticalAction(uint256 data, ROPType dtype) external onlyOwner {
        emit CriticalAction(msg.sender, dtype, ROPDefenseType.OwnerCheck);
        // ... critical logic ...
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ROLE‐ONLY CHECK & DELEGATION
//    • ✅ Defense: RoleCheck – only addresses with role  
//               DelegateCheck – owner can delegate role to others
////////////////////////////////////////////////////////////////////////////////
contract ROPSafeRole {
    mapping(address => bool) public hasRole;
    address public owner;
    event CriticalAction(address indexed who, ROPType dtype, ROPDefenseType defense);

    error ROP__NoRole();

    constructor() {
        owner = msg.sender;
        hasRole[msg.sender] = true;
    }

    modifier onlyRole() {
        if (!hasRole[msg.sender]) revert ROP__NoRole();
        _;
    }

    /// @notice Owner may grant or revoke roles
    function delegateRole(address user, bool ok) external {
        if (msg.sender != owner) revert ROP__NotOwner();
        hasRole[user] = ok;
    }

    function criticalAction(uint256 data, ROPType dtype) external onlyRole {
        emit CriticalAction(msg.sender, dtype, ROPDefenseType.DelegateCheck);
        // ... critical logic ...
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE COMPOSITE: ROLE‐OR‐OWNER & SIGNATURE VALIDATION & AUDIT
//    • ✅ Defense: CompositeCheck – allow if owner OR has role  
//               SignatureValidation – require owner‐signed payload for extra ops
////////////////////////////////////////////////////////////////////////////////
contract ROPSafeComposite {
    mapping(address => bool) public hasRole;
    address public owner;
    address public signer;

    event CriticalAction(address indexed who, ROPType dtype, ROPDefenseType defense);
    event AuditLog(address indexed who, uint256 data, ROPDefenseType defense);

    error ROP__NotCompositeAuthorized();
    error ROP__InvalidSignature();

    constructor(address _signer) {
        owner = msg.sender;
        signer = _signer;
        hasRole[msg.sender] = true;
    }

    modifier onlyRoleOrOwner() {
        if (msg.sender != owner && !hasRole[msg.sender]) revert ROP__NotCompositeAuthorized();
        _;
    }

    /// @notice Owner may grant or revoke roles
    function delegateRole(address user, bool ok) external {
        if (msg.sender != owner) revert ROP__NotOwner();
        hasRole[user] = ok;
    }

    /// @notice Protected critical action
    function criticalAction(uint256 data, ROPType dtype) external onlyRoleOrOwner {
        emit CriticalAction(msg.sender, dtype, ROPDefenseType.CompositeCheck);
        // ... critical logic ...
    }

    /// @notice Owner‐signed override for off‐chain authorized calls
    function criticalActionSigned(
        uint256 data,
        ROPType dtype,
        bytes calldata sig
    ) external {
        // verify signature over (msg.sender||data||dtype)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert ROP__InvalidSignature();

        emit CriticalAction(msg.sender, dtype, ROPDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, data, ROPDefenseType.AuditLogging);
        // ... critical logic ...
    }
}
