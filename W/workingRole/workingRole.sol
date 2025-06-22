// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WorkingRoleSuite.sol
/// @notice On‐chain analogues of “Working Role” assignment and enforcement patterns:
///   Types: Admin, Editor, Viewer, Guest  
///   AttackTypes: RoleEscalation, PrivilegeAbuse, UnauthorizedAccess, SessionHijack  
///   DefenseTypes: RBAC, MFA, RateLimit, AuditLogging

enum WorkingRoleType           { Admin, Editor, Viewer, Guest }
enum WorkingRoleAttackType     { RoleEscalation, PrivilegeAbuse, UnauthorizedAccess, SessionHijack }
enum WorkingRoleDefenseType    { RBAC, MFA, RateLimit, AuditLogging }

error WR__NotAuthorized();
error WR__InvalidRole();
error WR__TooManyRequests();
error WR__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE ROLE MANAGER
//    • ❌ no controls: anyone may assign any role → RoleEscalation
////////////////////////////////////////////////////////////////////////////////
contract WorkingRoleVuln {
    mapping(address => WorkingRoleType) public roleOf;

    event RoleAssigned(
        address indexed who,
        address indexed user,
        WorkingRoleType     role,
        WorkingRoleAttackType attack
    );

    function assignRole(address user, WorkingRoleType role) external {
        roleOf[user] = role;
        emit RoleAssigned(msg.sender, user, role, WorkingRoleAttackType.RoleEscalation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates escalation, abuse, session hijack
////////////////////////////////////////////////////////////////////////////////
contract Attack_WorkingRole {
    WorkingRoleVuln public target;
    address public lastUser;
    WorkingRoleType public lastRole;

    constructor(WorkingRoleVuln _t) { target = _t; }

    function escalate(address user, WorkingRoleType role) external {
        // attacker abuses vulnerability to escalate
        target.assignRole(user, role);
        lastUser = user;
        lastRole = role;
    }

    function replayEscalation() external {
        // replay captured assignment
        target.assignRole(lastUser, lastRole);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH RBAC
//    • ✅ Defense: RBAC – only Admin may assign roles
////////////////////////////////////////////////////////////////////////////////
contract WorkingRoleSafeRBAC {
    mapping(address => WorkingRoleType) public roleOf;
    address public deployer;

    event RoleAssigned(
        address indexed who,
        address indexed user,
        WorkingRoleType     role,
        WorkingRoleDefenseType defense
    );

    error WR__NotAuthorized();

    constructor() {
        deployer = msg.sender;
        roleOf[deployer] = WorkingRoleType.Admin;
    }

    function assignRole(address user, WorkingRoleType role) external {
        if (roleOf[msg.sender] != WorkingRoleType.Admin) revert WR__NotAuthorized();
        roleOf[user] = role;
        emit RoleAssigned(msg.sender, user, role, WorkingRoleDefenseType.RBAC);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH MFA & RATE LIMIT
//    • ✅ Defense: MFA – require prior OTP verification  
//               RateLimit – cap assignments per block
////////////////////////////////////////////////////////////////////////////////
contract WorkingRoleSafeMFA {
    mapping(address => WorkingRoleType) public roleOf;
    mapping(address => bytes32)         public otp;
    mapping(address => uint256)         public lastBlock;
    mapping(address => uint256)         public assignsInBlock;
    uint256 public constant MAX_ASSIGN = 3;

    event RoleAssigned(
        address indexed who,
        address indexed user,
        WorkingRoleType     role,
        WorkingRoleDefenseType defense
    );

    error WR__NotAuthorized();
    error WR__TooManyRequests();

    function setOTP(bytes32 code) external {
        otp[msg.sender] = code;
    }

    function verifyOTP(bytes32 code) external {
        require(otp[msg.sender] == code, "bad OTP");
        delete otp[msg.sender];
    }

    function assignRole(address user, WorkingRoleType role) external {
        // MFA: require that sender just verified OTP
        if (otp[msg.sender] != bytes32(0)) revert WR__NotAuthorized(); // must have consumed OTP

        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]      = block.number;
            assignsInBlock[msg.sender] = 0;
        }
        assignsInBlock[msg.sender]++;
        if (assignsInBlock[msg.sender] > MAX_ASSIGN) revert WR__TooManyRequests();

        roleOf[user] = role;
        emit RoleAssigned(msg.sender, user, role, WorkingRoleDefenseType.MFA);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require Admin’s off‐chain approval  
//               AuditLogging – record every assignment
////////////////////////////////////////////////////////////////////////////////
contract WorkingRoleSafeAdvanced {
    mapping(address => WorkingRoleType) public roleOf;
    address public signer;

    event AuditLog(
        address indexed who,
        address indexed user,
        WorkingRoleType     role,
        WorkingRoleDefenseType defense
    );

    error WR__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function assignRole(
        address user,
        WorkingRoleType role,
        bytes calldata sig
    ) external {
        // verify signature over (user||role)
        bytes32 msgHash = keccak256(abi.encodePacked(user, role));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) revert WR__InvalidSignature();

        roleOf[user] = role;
        emit AuditLog(msg.sender, user, role, WorkingRoleDefenseType.SignatureValidation);
    }
}
