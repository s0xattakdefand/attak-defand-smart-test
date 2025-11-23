// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
==============================================================
   ELECTRONIC COUNTERMEASURES (ECM) — SMART CONTRACT LAB
==============================================================

1) ElectronicCountermeasuresV1
      - Vulnerable ECM engine
      - Anyone can activate ECM, spoof responses, change jamming power
      - Anyone can delete threat logs

2) ElectronicCountermeasuresAttacker
      - Performs ECM sabotage
      - Spoofs jamming signals
      - Deletes high-intensity threat logs

3) ElectronicCountermeasuresV2Defense
      - Secure ECM subsystem for military/critical applications
      - Roles (OPERATOR, EW_ANALYST, COMMAND, ADMIN)
      - Strict ECM activation rules
      - Max power controls, no unauthorized ECM activations
      - Immutable event logs (no deletion)
*/


/* ========================================================= */
/* 1. VULNERABLE ECM SYSTEM (V1)                              */
/* ========================================================= */

contract ElectronicCountermeasuresV1 {

    struct ECMSystem {
        string name;
        bool ecmActive;
        uint256 jammingPower;  // 0–100 scale
        bool exists;
    }

    struct ThreatEvent {
        uint256 systemId;
        string threatType;     // "RADAR", "IR", "RF", etc.
        uint8 intensity;       // 1–10
        bool countered;
        uint64 timestamp;
        bool exists;
    }

    uint256 public systemCounter;
    uint256 public threatCounter;

    mapping(uint256 => ECMSystem) public systems;
    mapping(uint256 => ThreatEvent) public threats;
    mapping(uint256 => uint256[]) public systemThreats;

    event SystemRegistered(uint256 indexed systemId, string name);
    event ECMUpdated(uint256 indexed systemId, bool active, uint256 power);
    event ThreatLogged(uint256 indexed threatId, uint256 indexed systemId);
    event ThreatDeleted(uint256 indexed threatId);

    /*
     * ⚠️ VULNERABILITIES:
     *   - Anyone can:
     *       registerSystem
     *       activate ECM (ecmActive=true)
     *       set jammingPower to any value
     *       log fake threats
     *       delete threats
     */

    function registerSystem(string memory name)
        external
        returns (uint256)
    {
        systemCounter++;
        uint256 id = systemCounter;

        systems[id] = ECMSystem({
            name: name,
            ecmActive: false,
            jammingPower: 0,
            exists: true
        });

        emit SystemRegistered(id, name);
        return id;
    }

    function updateECM(uint256 systemId, bool active, uint256 power) external {
        ECMSystem storage s = systems[systemId];
        require(s.exists, "no system");

        s.ecmActive = active;
        s.jammingPower = power;

        emit ECMUpdated(systemId, active, power);
    }

    function logThreat(
        uint256 systemId,
        string memory threatType,
        uint8 intensity,
        bool countered
    ) external returns (uint256) {
        require(systems[systemId].exists, "no system");
        require(intensity >= 1 && intensity <= 10, "bad intensity");

        threatCounter++;
        uint256 tid = threatCounter;

        threats[tid] = ThreatEvent({
            systemId: systemId,
            threatType: threatType,
            intensity: intensity,
            countered: countered,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        systemThreats[systemId].push(tid);

        emit ThreatLogged(tid, systemId);
        return tid;
    }

    function deleteThreat(uint256 threatId) external {
        require(threats[threatId].exists, "no threat");
        delete threats[threatId];
        emit ThreatDeleted(threatId);
    }

    function getSystemThreats(uint256 systemId)
        external
        view
        returns (uint256[] memory)
    {
        return systemThreats[systemId];
    }
}


/* ========================================================= */
/* 2. ATTACKER — ECM SABOTAGE                                 */
/* ========================================================= */

contract ElectronicCountermeasuresAttacker {
    ElectronicCountermeasuresV1 public target;
    address public attacker;

    event ECMDisabled(uint256 indexed systemId);
    event FakeThreatErased(uint256 indexed threatId);

    constructor(address _target) {
        target = ElectronicCountermeasuresV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack:
     *   - Disable ECM on active system
     *   - Set jammingPower = 0
     *   - Erase severe threat logs (intensity >= 8)
     */

    function disableECM(uint256 systemId) external {
        require(msg.sender == attacker, "not attacker");

        target.updateECM(systemId, false, 0);
        emit ECMDisabled(systemId);
    }

    function eraseThreat(uint256 threatId) external {
        require(msg.sender == attacker, "not attacker");

        target.deleteThreat(threatId);
        emit FakeThreatErased(threatId);
    }
}


/* ========================================================= */
/* 3. SECURE ECM (V2 DEFENSE)                                 */
/* ========================================================= */

contract ElectronicCountermeasuresV2Defense {

    enum Role {
        NONE,
        OPERATOR,
        EW_ANALYST,
        COMMAND,
        ADMIN
    }

    struct ECMSystem {
        string name;
        bool ecmActive;
        uint256 jammingPower;
        uint256 maxPower;       // cannot exceed
        bool exists;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct ThreatEvent {
        uint256 systemId;
        string threatType;
        uint8 intensity;
        bool countered;
        address reportedBy;
        uint64 timestamp;
        bool exists;
    }

    address public systemAdmin;
    uint256 public systemCounter;
    uint256 public threatCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => ECMSystem) public systems;
    mapping(uint256 => ThreatEvent) public threats;
    mapping(uint256 => uint256[]) public systemThreats;

    event RoleAssigned(address indexed user, Role role);
    event SystemRegistered(uint256 indexed systemId, string name);
    event ECMUpdated(uint256 indexed systemId, bool active, uint256 power);
    event ThreatLogged(uint256 indexed threatId, uint256 indexed systemId);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyCommandOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.COMMAND || r == Role.ADMIN, "not command/admin");
        _;
    }

    modifier onlyAnalystOrHigher() {
        Role r = roles[msg.sender];
        require(
            r == Role.EW_ANALYST ||
            r == Role.COMMAND ||
            r == Role.ADMIN,
            "not ew/command/admin"
        );
        _;
    }

    modifier onlyOperatorOrHigher() {
        Role r = roles[msg.sender];
        require(
            r == Role.OPERATOR ||
            r == Role.EW_ANALYST ||
            r == Role.COMMAND ||
            r == Role.ADMIN,
            "not operator/ew/command/admin"
        );
        _;
    }

    constructor() {
        systemAdmin = msg.sender;
        roles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    /* ---------------- ROLE MANAGEMENT ---------------- */

    function assignRole(address user, Role r) external onlyAdmin {
        require(user != address(0), "zero");
        require(r != Role.NONE, "invalid");

        roles[user] = r;
        emit RoleAssigned(user, r);
    }

    /* ---------------- SYSTEM REGISTRATION ------------- */

    function registerSystem(string memory name, uint256 maxPower)
        external
        onlyCommandOrAdmin
        returns (uint256)
    {
        require(bytes(name).length > 0, "name required");
        require(maxPower > 0 && maxPower <= 100, "max power bad");

        systemCounter++;
        uint256 id = systemCounter;

        systems[id] = ECMSystem({
            name: name,
            ecmActive: false,
            jammingPower: 0,
            maxPower: maxPower,
            exists: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit SystemRegistered(id, name);
        return id;
    }

    /* ---------------- ECM CONTROL --------------------- */

    function updateECM(uint256 systemId, bool active, uint256 power)
        external
        onlyAnalystOrHigher
    {
        ECMSystem storage s = systems[systemId];
        require(s.exists, "no system");
        require(power <= s.maxPower, "exceeds max");

        s.ecmActive = active;
        s.jammingPower = power;
        s.updatedAt = uint64(block.timestamp);

        emit ECMUpdated(systemId, active, power);
    }

    /* ---------------- THREAT LOGGING ------------------ */

    function logThreat(
        uint256 systemId,
        string memory threatType,
        uint8 intensity,
        bool countered
    )
        external
        onlyOperatorOrHigher
        returns (uint256)
    {
        require(systems[systemId].exists, "no system");
        require(bytes(threatType).length > 0, "type required");
        require(intensity >= 1 && intensity <= 10, "bad intensity");

        threatCounter++;
        uint256 tid = threatCounter;

        threats[tid] = ThreatEvent({
            systemId: systemId,
            threatType: threatType,
            intensity: intensity,
            countered: countered,
            reportedBy: msg.sender,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        systemThreats[systemId].push(tid);

        emit ThreatLogged(tid, systemId);
        return tid;
    }

    /* ---------------- VIEW HELPERS -------------------- */

    function getThreat(uint256 id)
        external
        view
        returns (
            uint256 systemId,
            string memory threatType,
            uint8 intensity,
            bool countered,
            address reportedBy,
            uint64 timestamp,
            bool exists
        )
    {
        ThreatEvent storage t = threats[id];
        return (
            t.systemId,
            t.threatType,
            t.intensity,
            t.countered,
            t.reportedBy,
            t.timestamp,
            t.exists
        );
    }

    function getSystemThreats(uint256 id)
        external
        view
        returns (uint256[] memory)
    {
        return systemThreats[id];
    }

    function getSystem(uint256 systemId)
        external
        view
        returns (
            string memory name,
            bool ecmActive,
            uint256 jammingPower,
            uint256 maxPower,
            bool exists,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        ECMSystem storage s = systems[systemId];
        return (
            s.name,
            s.ecmActive,
            s.jammingPower,
            s.maxPower,
            s.exists,
            s.createdAt,
            s.updatedAt
        );
    }
}
