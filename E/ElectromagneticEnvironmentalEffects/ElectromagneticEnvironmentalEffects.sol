// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTROMAGNETIC ENVIRONMENTAL EFFECTS (E3) – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *   1) ElectromagneticEnvironmentalEffectsV1          – vulnerable E3 risk registry
 *   2) ElectromagneticEnvironmentalEffectsAttacker    – attacker that hides/forges risk
 *   3) ElectromagneticEnvironmentalEffectsV2Defense   – secure, role-based E3 risk manager
 *
 *  Concept:
 *    - Critical sites (data centers, substations, radar, comms towers) are exposed to
 *      electromagnetic environmental effects: solar storms, EMP, lightning, HF jamming.
 *
 *    - We track:
 *        * Sites (name, critical flag)
 *        * E3 events (type, severity 1–10)
 *        * Aggregated riskScore per site
 *
 *    V1 BUGS:
 *      - Anyone can:
 *          * register and modify sites (critical flag, name)
 *          * reduce riskScore to 0 (hide real risk)
 *          * delete events (erase evidence)
 *
 *    V2 FIXES:
 *      - Roles: ADMIN, RISK_ENGINEER
 *      - Events are immutable (no delete / overwrite)
 *      - riskScore is derived from events only (no manual “set 0”)
 *      - Critical flag can’t be downgraded casually
 */


/* ============================================================= */
/*      1. VULNERABLE ELECTROMAGNETIC ENVIRONMENTAL EFFECTS V1   */
/* ============================================================= */

contract ElectromagneticEnvironmentalEffectsV1 {
    struct Site {
        string name;
        bool critical;
        uint256 riskScore; // aggregated manual score (0–100+, no real rules here)
        bool exists;
    }

    struct Event {
        string eventType;  // "SolarStorm", "Lightning", "EMP", "Jamming", etc.
        uint8 severity;    // 1–10
        uint64 timestamp;
        bool exists;
    }

    uint256 public siteCounter;
    uint256 public eventCounter;

    mapping(uint256 => Site) public sites;
    mapping(uint256 => Event) public events;
    mapping(uint256 => uint256[]) public siteEvents; // siteId => event IDs

    event SiteRegistered(uint256 indexed siteId, string name, bool critical);
    event SiteUpdated(uint256 indexed siteId, string name, bool critical, uint256 riskScore);
    event EventRecorded(uint256 indexed eventId, uint256 indexed siteId, string eventType, uint8 severity);
    event EventDeleted(uint256 indexed eventId);

    /*
     * ⚠️ V1 – NO ACCESS CONTROL
     *   - ANYONE can:
     *       registerSite, updateSiteRisk, recordEvent, deleteEvent
     *   - Hiding risk is trivial: set riskScore=0 and delete bad events.
     */

    function registerSite(
        string memory name,
        bool critical,
        uint256 initialRisk
    ) external returns (uint256) {
        require(bytes(name).length > 0, "name required");

        siteCounter++;
        uint256 id = siteCounter;

        sites[id] = Site({
            name: name,
            critical: critical,
            riskScore: initialRisk,
            exists: true
        });

        emit SiteRegistered(id, name, critical);
        return id;
    }

    function updateSiteRisk(
        uint256 siteId,
        string memory newName,
        bool newCritical,
        uint256 newRiskScore
    ) external {
        Site storage s = sites[siteId];
        require(s.exists, "no site");

        s.name = newName;
        s.critical = newCritical;
        s.riskScore = newRiskScore; // ⚠️ direct manual override

        emit SiteUpdated(siteId, newName, newCritical, newRiskScore);
    }

    function recordEvent(
        uint256 siteId,
        string memory eventType,
        uint8 severity
    ) external returns (uint256) {
        require(sites[siteId].exists, "no site");
        require(bytes(eventType).length > 0, "eventType required");
        require(severity >= 1 && severity <= 10, "bad severity");

        eventCounter++;
        uint256 eid = eventCounter;

        events[eid] = Event({
            eventType: eventType,
            severity: severity,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        siteEvents[siteId].push(eid);

        // naive: higher severity adds more "risk", but anyone can later zero it
        sites[siteId].riskScore += severity;

        emit EventRecorded(eid, siteId, eventType, severity);
        return eid;
    }

    // ⚠️ Anyone can erase history
    function deleteEvent(uint256 eventId) external {
        require(events[eventId].exists, "no event");
        delete events[eventId];
        emit EventDeleted(eventId);
    }

    function getSite(uint256 siteId)
        external
        view
        returns (string memory name, bool critical, uint256 riskScore, bool exists)
    {
        Site storage s = sites[siteId];
        return (s.name, s.critical, s.riskScore, s.exists);
    }

    function getSiteEvents(uint256 siteId) external view returns (uint256[] memory) {
        return siteEvents[siteId];
    }
}


/* ============================================================= */
/*              2. ATTACKER – HIDE & FORGE E3 RISK               */
/* ============================================================= */

contract ElectromagneticEnvironmentalEffectsAttacker {
    ElectromagneticEnvironmentalEffectsV1 public target;
    address public attacker;

    event SiteRiskHidden(uint256 indexed siteId, uint256 newRisk);
    event BadEventErased(uint256 indexed eventId);

    constructor(address _target) {
        target = ElectromagneticEnvironmentalEffectsV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack strategy:
     *  - For a high-risk critical site:
     *     1) Overwrite riskScore to a low value or 0.
     *     2) Optionally rename site to something benign.
     *     3) Delete high-severity events from history.
     */

    function hideRisk(uint256 siteId, string calldata spoofedName) external {
        require(msg.sender == attacker, "not attacker");

        // Set riskScore to 0, pretend it's non-critical
        target.updateSiteRisk(siteId, spoofedName, false, 0);
        emit SiteRiskHidden(siteId, 0);
    }

    function eraseEvent(uint256 eventId) external {
        require(msg.sender == attacker, "not attacker");
        target.deleteEvent(eventId);
        emit BadEventErased(eventId);
    }
}


/* ============================================================= */
/*       3. SECURE ELECTROMAGNETIC ENVIRONMENTAL EFFECTS V2      */
/* ============================================================= */

contract ElectromagneticEnvironmentalEffectsV2Defense {
    enum Role {
        NONE,
        RISK_ENGINEER,
        ADMIN
    }

    struct Site {
        string name;
        bool critical;
        bool exists;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct E3Event {
        string eventType;
        uint8 severity;     // 1–10
        uint64 timestamp;
        uint256 siteId;
        bool exists;
    }

    address public systemAdmin;
    uint256 public siteCounter;
    uint256 public eventCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => Site) public sites;
    mapping(uint256 => E3Event) public events;
    mapping(uint256 => uint256[]) public siteEvents; // siteId => event IDs

    event RoleAssigned(address indexed account, Role role);
    event SiteRegistered(uint256 indexed siteId, string name, bool critical);
    event SiteUpdated(uint256 indexed siteId, string name, bool critical);
    event E3EventRecorded(
        uint256 indexed eventId,
        uint256 indexed siteId,
        string eventType,
        uint8 severity
    );
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyRiskEngineerOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.RISK_ENGINEER || r == Role.ADMIN, "not risk engineer/admin");
        _;
    }

    constructor() {
        systemAdmin = msg.sender;
        roles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    // ----------------- ROLE MANAGEMENT -----------------

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

    // ----------------- SITE MANAGEMENT -----------------

    function registerSite(
        string memory name,
        bool critical
    ) external onlyAdmin returns (uint256) {
        require(bytes(name).length > 0, "name required");

        siteCounter++;
        uint256 id = siteCounter;

        sites[id] = Site({
            name: name,
            critical: critical,
            exists: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit SiteRegistered(id, name, critical);
        return id;
    }

    function updateSite(
        uint256 siteId,
        string memory newName,
        bool keepCritical // cannot downgrade critical→non-critical via this flag
    ) external onlyAdmin {
        Site storage s = sites[siteId];
        require(s.exists, "no site");
        require(bytes(newName).length > 0, "name required");

        s.name = newName;
        if (s.critical) {
            // once critical, stay critical in this function
            s.critical = true;
        } else {
            s.critical = keepCritical;
        }
        s.updatedAt = uint64(block.timestamp);

        emit SiteUpdated(siteId, s.name, s.critical);
    }

    // ----------------- EVENT RECORDING -----------------

    /*
     *  E3 events are IMMUTABLE in V2:
     *   - No delete, no overwrite.
     *   - Risk is derived OFF-CHAIN from events:
     *       riskScore = f(severity, count, time decay, critical flag)
     */

    function recordE3Event(
        uint256 siteId,
        string memory eventType,
        uint8 severity
    ) external onlyRiskEngineerOrAdmin returns (uint256) {
        Site storage s = sites[siteId];
        require(s.exists, "no site");
        require(bytes(eventType).length > 0, "eventType required");
        require(severity >= 1 && severity <= 10, "bad severity");

        eventCounter++;
        uint256 eid = eventCounter;

        events[eid] = E3Event({
            eventType: eventType,
            severity: severity,
            timestamp: uint64(block.timestamp),
            siteId: siteId,
            exists: true
        });

        siteEvents[siteId].push(eid);

        emit E3EventRecorded(eid, siteId, eventType, severity);
        return eid;
    }

    // ----------------- VIEW HELPERS -----------------

    function getSite(uint256 siteId)
        external
        view
        returns (
            string memory name,
            bool critical,
            bool exists,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        Site storage s = sites[siteId];
        return (s.name, s.critical, s.exists, s.createdAt, s.updatedAt);
    }

    function getSiteEvents(uint256 siteId) external view returns (uint256[] memory) {
        return siteEvents[siteId];
    }

    function getEvent(uint256 eventId)
        external
        view
        returns (
            string memory eventType,
            uint8 severity,
            uint64 timestamp,
            uint256 siteId,
            bool exists
        )
    {
        E3Event storage e = events[eventId];
        return (e.eventType, e.severity, e.timestamp, e.siteId, e.exists);
    }
}
