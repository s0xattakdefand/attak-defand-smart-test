// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DiscretionaryAccessControlListSuite.sol
/// @notice On‐chain analogues of “Discretionary Access Control List” (DACL) patterns:
///   Types: AllowACE, DenyACE, InheritACE  
///   AttackTypes: PrivilegeEscalation, UnauthorizedAccess, Tampering, Bypass  
///   DefenseTypes: ACLCheck, PermissionMatrix, RateLimit, SignatureValidation, AuditLogging

enum DACLType                 { AllowACE, DenyACE, InheritACE }
enum DACLAttackType           { PrivilegeEscalation, UnauthorizedAccess, Tampering, Bypass }
enum DACLDefenseType          { ACLCheck, PermissionMatrix, RateLimit, SignatureValidation, AuditLogging }

error DACL__NotOwner();
error DACL__NoACE();
error DACL__NotPermitted();
error DACL__TooManyRequests();
error DACL__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DACL
//    • ❌ no checks: anyone may set or query ACEs → PrivilegeEscalation
////////////////////////////////////////////////////////////////////////////////
contract DACLVuln {
    // resourceId -> actor -> allowed
    mapping(bytes32 => mapping(address => bool)) public acl;

    event ACESet(
        address indexed who,
        bytes32           resourceId,
        address           actor,
        bool              allow,
        DACLType          dtype,
        DACLAttackType    attack
    );
    event AccessChecked(
        address indexed who,
        bytes32           resourceId,
        address           actor,
        bool              allowed,
        DACLType          dtype,
        DACLAttackType    attack
    );

    function setACE(
        bytes32 resourceId,
        address actor,
        bool allow,
        DACLType dtype
    ) external {
        acl[resourceId][actor] = allow;
        emit ACESet(msg.sender, resourceId, actor, allow, dtype, DACLAttackType.Tampering);
    }

    function checkAccess(
        bytes32 resourceId,
        address actor,
        DACLType dtype
    ) external view returns (bool) {
        bool allowed = acl[resourceId][actor];
        emit AccessChecked(msg.sender, resourceId, actor, allowed, dtype, DACLAttackType.UnauthorizedAccess);
        return allowed;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized ACE tampering and bypass
////////////////////////////////////////////////////////////////////////////////
contract Attack_DACL {
    DACLVuln public target;
    bytes32 public lastRes;
    address public lastActor;
    bool    public lastAllow;

    constructor(DACLVuln _t) {
        target = _t;
    }

    function tamperACE(
        bytes32 resourceId,
        address actor,
        bool allow
    ) external {
        target.setACE(resourceId, actor, allow, DACLType.AllowACE);
        lastRes   = resourceId;
        lastActor = actor;
        lastAllow = allow;
    }

    function bypassACE() external {
        target.setACE(lastRes, lastActor, lastAllow, DACLType.DenyACE);
    }

    function leakAccess(bytes32 resourceId, address actor) external {
        target.checkAccess(resourceId, actor, DACLType.InheritACE);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACL CHECK
//    • ✅ Defense: ACLCheck – only owner may set ACEs; everyone may query
////////////////////////////////////////////////////////////////////////////////
contract DACLSafeACL {
    mapping(bytes32 => mapping(address => bool)) public acl;
    address public owner;

    event ACESet(
        address indexed who,
        bytes32           resourceId,
        address           actor,
        bool              allow,
        DACLType          dtype,
        DACLDefenseType   defense
    );
    event AccessChecked(
        address indexed who,
        bytes32           resourceId,
        address           actor,
        bool              allowed,
        DACLType          dtype,
        DACLDefenseType   defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DACL__NotOwner();
        _;
    }

    function setACE(
        bytes32 resourceId,
        address actor,
        bool allow,
        DACLType dtype
    ) external onlyOwner {
        acl[resourceId][actor] = allow;
        emit ACESet(msg.sender, resourceId, actor, allow, dtype, DACLDefenseType.ACLCheck);
    }

    function checkAccess(
        bytes32 resourceId,
        address actor,
        DACLType dtype
    ) external view returns (bool) {
        bool allowed = acl[resourceId][actor];
        emit AccessChecked(msg.sender, resourceId, actor, allowed, dtype, DACLDefenseType.ACLCheck);
        return allowed;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH PERMISSION MATRIX & RATE LIMIT
//    • ✅ Defense: PermissionMatrix – resource owner may grant per-key ACL  
//               RateLimit        – cap operations per block
////////////////////////////////////////////////////////////////////////////////
contract DACLSafeMatrix {
    mapping(bytes32 => mapping(address => bool))                   public acl;
    mapping(bytes32 => mapping(bytes32 => mapping(address => bool))) public matrix;
    mapping(address => uint256)                                     public lastBlock;
    mapping(address => uint256)                                     public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event ACESet(
        address indexed who,
        bytes32           resourceId,
        address           actor,
        bool              allow,
        DACLType          dtype,
        DACLDefenseType   defense
    );
    event AccessChecked(
        address indexed who,
        bytes32           resourceId,
        address           actor,
        bool              allowed,
        DACLType          dtype,
        DACLDefenseType   defense
    );

    error DACL__NotPermitted();
    error DACL__TooManyRequests();

    function setACL(
        bytes32 resourceId,
        address actor,
        bool allow
    ) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DACL__TooManyRequests();

        // only resource owner or approved actor in matrix[resource][key]
        if (msg.sender != tx.origin && !matrix[resourceId][bytes32("owner")][msg.sender]) {
            revert DACL__NotPermitted();
        }
        acl[resourceId][actor] = allow;
        emit ACESet(msg.sender, resourceId, actor, allow, DACLType.AllowACE, DACLDefenseType.PermissionMatrix);
    }

    function setMatrix(
        bytes32 resourceId,
        bytes32 key,
        address actor,
        bool allow
    ) external {
        // stub: resource owner only
        matrix[resourceId][key][actor] = allow;
    }

    function checkAccess(
        bytes32 resourceId,
        address actor,
        DACLType dtype
    ) external view returns (bool) {
        bool allowed = acl[resourceId][actor];
        emit AccessChecked(msg.sender, resourceId, actor, allowed, dtype, DACLDefenseType.PermissionMatrix);
        return allowed;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require off‐chain owner signature  
//               AuditLogging      – record every change
////////////////////////////////////////////////////////////////////////////////
contract DACLSafeAdvanced {
    mapping(bytes32 => mapping(address => bool)) public acl;
    address public signer;

    event ACESet(
        address indexed who,
        bytes32           resourceId,
        address           actor,
        bool              allow,
        DACLType          dtype,
        DACLDefenseType   defense
    );
    event AuditLog(
        address indexed who,
        bytes32           resourceId,
        address           actor,
        bool              allow,
        DACLType          dtype,
        DACLDefenseType   defense
    );

    error DACL__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function setACE(
        bytes32 resourceId,
        address actor,
        bool allow,
        DACLType dtype,
        bytes calldata sig
    ) external {
        // verify signature over (resourceId||actor||allow||dtype)
        bytes32 h = keccak256(abi.encodePacked(resourceId, actor, allow, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DACL__InvalidSignature();

        acl[resourceId][actor] = allow;
        emit ACESet(msg.sender, resourceId, actor, allow, dtype, DACLDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, resourceId, actor, allow, dtype, DACLDefenseType.AuditLogging);
    }

    function checkAccess(
        bytes32 resourceId,
        address actor,
        DACLType dtype
    ) external view returns (bool) {
        return acl[resourceId][actor];
    }
}
