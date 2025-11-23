// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTRONIC COUNTER-COUNTERMEASURES (ECCM) – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *   1) ElectronicCounterCountermeasuresV1
 *        – vulnerable ECCM configuration + threat logging
 *
 *   2) ElectronicCounterCountermeasuresAttacker
 *        – attacker that disables ECCM, lowers resilience, wipes threat events
 *
 *   3) ElectronicCounterCountermeasuresV2Defense
 *        – secure ECCM registry with roles, immutable logs, and guarded updates
 *
 *  Concept:
 *    - Systems (radars, comm links, sensors) are registered with ECCM settings:
 *        * eccmEnabled (true/false)
 *        * resilienceScore (higher = more resistant to jamming/spoofing)
 *        * critical flag
 *
 *    - Threat events are logged when jamming / spoofing attempts are detected.
 *
 *    V1 BUGS:
 *      - Anyone can:
 *          * disable ECCM (eccmEnabled=false)
 *          * arbitrarily change resilienceScore
 *          * mark critical systems as non-critical
 *          * delete threat events
 *
 *    V2 FIXES:
 *      - Roles: OPERATOR, EW_ANALYST, COMMAND, ADMIN
 *      - Only COMMAND/ADMIN can register systems or flip critical flag
 *      - Only EW_ANALYST/COMMAND/ADMIN can tune resilience/ECCM
 *      - Threat logs are immutable (no delete)
 *      - Resilience cannot be dropped below configured minimum
 */


/* ============================================================= */
/*   1. VULNERABLE ELECTRONIC COUNTER-COUNTERMEASURES (V1)       */
/* ============================================================= */

contract ElectronicCounterCountermeasuresV1 {
    struct System {
        string name;             // e.g., "Radar-Alpha", "SATCOM-Link-1"
        bool critical;           // mission critical
        bool eccmEnabled;        // ECCM active or not
        uint256 resilienceScore; // arbitrary score 0–100
        bool exists;
    }

    struct ThreatEvent {
        uint256 systemId;
        string threatType;       // "NoiseJamming", "Deception", "Spoofing", etc.
        uint8 intensity;         // 1–10
        bool eccmResponded;      // whether ECCM was triggered
        uint64 timestamp;
        bool exists;
    }

    uint256 public systemCounter;
    uint256 public threatCounter;

    mapping(uint256 => System) public systems;
    mapping(uint256 => ThreatEvent) public threats;
    mapping(uint256 => uint256[]) public systemThreats; // systemId => threat IDs

    event SystemRegistered(
        uint256 indexed systemId,
        string name,
        bool critical,
        bool eccmEnabled,
        uint256 resilienceScore
    );

    event SystemUpdated(
        uint256 indexed systemId,
        bool critical,
        bool eccmEnabled,
        uint256 resilienceScore
    );

    event ThreatLogged(
        uint256 indexed threatId,
        uint256 indexed systemId,
        string threatType,
        uint8 intensity,
        bool eccmResponded
    );

    event ThreatDeleted(uint256 indexed threatId);

    /*
     * ⚠️ V1 – NO ACCESS CONTROL
     *   - ANY address can:
     *       registerSystem, updateSystem, logThreat, deleteThreat
     *   - Attacker can silently:
     *       * disable ECCM
     *       * set resilienceScore = 0
     *       * declare critical systems as non-critical
     *       * remove all severe threat logs
     */

    function registerSystem(
        string memory name,
        bool critical,
        bool eccmEnabled,
        uint256 resilienceScore
    ) external returns (uint256) {
        require(bytes(name).length > 0, "name required");

        systemCounter++;
        uint256 id = systemCounter;

        systems[id] = System({
            name: name,
            critical: critical,
            eccmEnabled: eccmEnabled,
            resilienceScore: resilienceScore,
            exists: true
        });

        emit SystemRegistered(id, name, critical, eccmEnabled, resilienceScore);
        return id;
    }

    // ⚠️ Anyone can flip ECCM and lower resilience
    function updateSystem(
        uint256 systemId,
        bool critical,
        bool eccmEnabled,
        uint256 resilienceScore
    ) external {
        System storage s = systems[systemId];
        require(s.exists, "no system");

        s.critical = critical;
        s.eccmEnabled = eccmEnabled;
        s.resilienceScore = resilienceScore;

        emit SystemUpdated(systemId, critical, eccmEnabled, resilienceScore);
    }

    function logThreat(
        uint256 systemId,
        string memory threatType,
        uint8 intensity,
        bool eccmResponded
    ) external returns (uint256) {
        System storage s = systems[systemId];
        require(s.exists, "no system");
        require(bytes(threatType).length > 0, "type required");
        require(intensity >= 1 && intensity <= 10, "bad intensity");

        threatCounter++;
        uint256 tid = threatCounter;

        threats[tid] = ThreatEvent({
            systemId: systemId,
            threatType: threatType,
            intensity: intensity,
            eccmResponded: eccmResponded,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        systemThreats[systemId].push(tid);

        emit ThreatLogged(tid, systemId, threatType, intensity, eccmResponded);
        return tid;
    }

    // ⚠️ Anyone can erase threat history
    function deleteThreat(uint256 threatId) external {
        require(threats[threatId].exists, "no threat");
        delete threats[threatId];
        emit ThreatDeleted(threatId);
    }

    function getSystem(uint256 systemId)
        external
        view
        returns (
            string memory name,
            bool critical,
            bool eccmEnabled,
            uint256 resilienceScore,
            bool exists
        )
    {
        System storage s = systems[systemId];
        return (s.name, s.critical, s.eccmEnabled, s.resilienceScore, s.exists);
    }

    function getThreat(uint256 threatId)
        external
        view
        returns (
            uint256 systemId,
            string memory threatType,
            uint8 intensity,
            bool eccmResponded,
            uint64 timestamp,
            bool exists
        )
    {
        ThreatEvent storage t = threats[threatId];
        return (
            t.systemId,
            t.threatType,
            t.intensity,
            t.eccmResponded,
            t.timestamp,
            t.exists
        );
    }

    function getSystemThreats(uint256 systemId) external view returns (uint256[] memory) {
        return systemThreats[systemId];
    }
}


/* ============================================================= */
/*  2. ATTACKER – DISABLE ECCM & WIPE ELECTRONIC WARFARE LOGS    */
/* ============================================================= */

contract ElectronicCounterCountermeasuresAttacker {
    ElectronicCounterCountermeasuresV1 public target;
    address public attacker;

    event ECCMDisabled(uint256 indexed systemId, uint256 newResilienceScore);
    event ThreatErased(uint256 indexed threatId);

    constructor(address _target) {
        target = ElectronicCounterCountermeasuresV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack pattern:
     *   - For a critical radar / comm link:
     *       1) Set critical=false (hide importance)
     *       2) Disable ECCM (eccmEnabled=false)
     *       3) Set resilienceScore = 0
     *   - Then wipe all severe threat logs for that system.
     */

    function sabotageSystem(uint256 systemId) external {
        require(msg.sender == attacker, "not attacker");

        // Try to fully disable protection
        target.updateSystem(systemId, false, false, 0);
        emit ECCMDisabled(systemId, 0);
    }

    function wipeThreat(uint256 threatId) external {
        require(msg.sender == attacker, "not attacker");
        target.deleteThreat(threatId);
        emit ThreatErased(threatId);
    }
}


/* ============================================================= */
/* 3. SECURE ELECTRONIC COUNTER-COUNTERMEASURES (V2 DEFENSE)     */
/* ============================================================= */

contract ElectronicCounterCountermeasuresV2Defense {
    enum Role {
        NONE,
        OPERATOR,
        EW_ANALYST,
        COMMAND,
        ADMIN
    }

    struct System {
        string name;
        bool critical;
        bool eccmEnabled;
        uint256 resilienceScore;
        uint256 minResilience;      // minimum allowed resilience
        bool exists;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct ThreatEvent {
        uint256 systemId;
        string threatType;
        uint8 intensity;
        bool eccmResponded;
        address reportedBy;
        uint64 timestamp;
        bool exists;
    }

    address public systemAdmin;
    uint256 public systemCounter;
    uint256 public threatCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => System) public systems;
    mapping(uint256 => ThreatEvent) public threats;
    mapping(uint256 => uint256[]) public systemThreats;

    event RoleAssigned(address indexed account, Role role);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    event SystemRegistered(
        uint256 indexed systemId,
        string name,
        bool critical,
        bool eccmEnabled,
        uint256 resilienceScore,
        uint256 minResilience
    );

    event SystemECCMUpdated(
        uint256 indexed systemId,
        bool eccmEnabled,
        uint256 resilienceScore,
        address updatedBy
    );

    event SystemCriticalityUpdated(
        uint256 indexed systemId,
        bool critical,
        address updatedBy
    );

    event ThreatLogged(
        uint256 indexed threatId,
        uint256 indexed systemId,
        string threatType,
        uint8 intensity,
        bool eccmResponded,
        address reportedBy
    );

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
            r == Role.EW_ANALYST || r == Role.COMMAND || r == Role.ADMIN,
            "not analyst/command/admin"
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
            "not operator/analyst/command/admin"
        );
        _;
    }

    constructor() {
        systemAdmin = msg.sender;
        roles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    // ---------------- ROLE MANAGEMENT ----------------

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

    // ---------------- SYSTEM MANAGEMENT ----------------

    /*
     * Register a new ECCM-protected system.
     *   - Only COMMAND or ADMIN
     *   - Set initial resilienceScore and minResilience
     */
    function registerSystem(
        string memory name,
        bool critical,
        bool eccmEnabled,
        uint256 resilienceScore,
        uint256 minResilience
    ) external onlyCommandOrAdmin returns (uint256) {
        require(bytes(name).length > 0, "name required");
        require(minResilience <= resilienceScore, "min > score");

        systemCounter++;
        uint256 id = systemCounter;

        systems[id] = System({
            name: name,
            critical: critical,
            eccmEnabled: eccmEnabled,
            resilienceScore: resilienceScore,
            minResilience: minResilience,
            exists: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit SystemRegistered(
            id,
            name,
            critical,
            eccmEnabled,
            resilienceScore,
            minResilience
        );
        return id;
    }

    /*
     * Update ECCM state and resilience score:
     *   - Only EW_ANALYST, COMMAND, or ADMIN
     *   - Cannot reduce resilience below minResilience
     */
    function tuneECCM(
        uint256 systemId,
        bool eccmEnabled,
        uint256 newResilienceScore
    ) external onlyAnalystOrHigher {
        System storage s = systems[systemId];
        require(s.exists, "no system");
        require(newResilienceScore >= s.minResilience, "below minimum");

        s.eccmEnabled = eccmEnabled;
        s.resilienceScore = newResilienceScore;
        s.updatedAt = uint64(block.timestamp);

        emit SystemECCMUpdated(systemId, eccmEnabled, newResilienceScore, msg.sender);
    }

    /*
     * Change criticality:
     *   - Only COMMAND or ADMIN
     */
    function setCritical(
        uint256 systemId,
        bool critical
    ) external onlyCommandOrAdmin {
        System storage s = systems[systemId];
        require(s.exists, "no system");

        s.critical = critical;
        s.updatedAt = uint64(block.timestamp);

        emit SystemCriticalityUpdated(systemId, critical, msg.sender);
    }

    // ---------------- THREAT LOGGING ----------------

    /*
     * Log a threat event:
     *   - Only OPERATOR, ANALYST, COMMAND, or ADMIN
     *   - No delete function; logs are immutable
     */
    function logThreat(
        uint256 systemId,
        string memory threatType,
        uint8 intensity,
        bool eccmResponded
    ) external onlyOperatorOrHigher returns (uint256) {
        System storage s = systems[systemId];
        require(s.exists, "no system");
        require(bytes(threatType).length > 0, "type required");
        require(intensity >= 1 && intensity <= 10, "bad intensity");

        threatCounter++;
        uint256 tid = threatCounter;

        threats[tid] = ThreatEvent({
            systemId: systemId,
            threatType: threatType,
            intensity: intensity,
            eccmResponded: eccmResponded,
            reportedBy: msg.sender,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        systemThreats[systemId].push(tid);

        emit ThreatLogged(
            tid,
            systemId,
            threatType,
            intensity,
            eccmResponded,
            msg.sender
        );
        return tid;
    }

    // ---------------- VIEW HELPERS ----------------

    function getSystem(uint256 systemId)
        external
        view
        returns (
            string memory name,
            bool critical,
            bool eccmEnabled,
            uint256 resilienceScore,
            uint256 minResilience,
            bool exists,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        System storage s = systems[systemId];
        return (
            s.name,
            s.critical,
            s.eccmEnabled,
            s.resilienceScore,
            s.minResilience,
            s.exists,
            s.createdAt,
            s.updatedAt
        );
    }

    function getThreat(uint256 threatId)
        external
        view
        returns (
            uint256 systemId,
            string memory threatType,
            uint8 intensity,
            bool eccmResponded,
            address reportedBy,
            uint64 timestamp,
            bool exists
        )
    {
        ThreatEvent storage t = threats[threatId];
        return (
            t.systemId,
            t.threatType,
            t.intensity,
            t.eccmResponded,
            t.reportedBy,
            t.timestamp,
            t.exists
        );
    }

    function getSystemThreats(uint256 systemId) external view returns (uint256[] memory) {
        return systemThreats[systemId];
    }
}
