// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTROMAGNETIC PULSE (EMP) – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *   1) ElectromagneticPulseV1          – vulnerable EMP risk registry
 *   2) ElectromagneticPulseAttacker    – attacker that hides/forges EMP risk
 *   3) ElectromagneticPulseV2Defense   – secure, role-based EMP risk manager
 *
 *  Concept:
 *    - Critical sites (data centers, substations, bunkers, command centers) can be affected
 *      by Electromagnetic Pulse (EMP) events, from high-altitude bursts or localized EMP.
 *
 *    - We track:
 *        * Facilities (name, hardened flag)
 *        * EMP events (category, severity 1–10)
 *        * Aggregate empRiskScore per facility
 *
 *    V1 BUGS:
 *      - Anyone can:
 *          * register and modify facilities (hardened flag, name)
 *          * reduce empRiskScore to 0 (hide real risk)
 *          * delete EMP events (erase evidence)
 *
 *    V2 FIXES:
 *      - Roles: ADMIN, EMP_ENGINEER
 *      - Events are immutable (no delete / overwrite)
 *      - riskScore is derived OFF-CHAIN from events (no manual “set 0”)
 *      - Hardened flag can’t be casually downgraded
 */


/* ============================================================= */
/*           1. VULNERABLE ELECTROMAGNETIC PULSE (V1)            */
/* ============================================================= */

contract ElectromagneticPulseV1 {
    struct Facility {
        string name;
        bool hardened;          // true if EMP-hardened
        uint256 empRiskScore;   // arbitrary manual score
        bool exists;
    }

    struct EMPEvent {
        string category;        // "HighAltitude", "Localized", "Test", etc.
        uint8 severity;         // 1–10
        uint64 timestamp;
        bool exists;
    }

    uint256 public facilityCounter;
    uint256 public eventCounter;

    mapping(uint256 => Facility) public facilities;
    mapping(uint256 => EMPEvent) public events;
    mapping(uint256 => uint256[]) public facilityEvents; // facilityId => event IDs

    event FacilityRegistered(uint256 indexed facilityId, string name, bool hardened);
    event FacilityUpdated(uint256 indexed facilityId, string name, bool hardened, uint256 empRiskScore);
    event EMPEventRecorded(
        uint256 indexed eventId,
        uint256 indexed facilityId,
        string category,
        uint8 severity
    );
    event EMPEventDeleted(uint256 indexed eventId);

    /*
     * ⚠️ V1 – NO ACCESS CONTROL
     *   - ANY address can:
     *       registerFacility, updateFacilityRisk, recordEMPEvent, deleteEMPEvent
     *   - Hiding EMP risk is trivial: set empRiskScore=0 and delete serious events.
     */

    function registerFacility(
        string memory name,
        bool hardened,
        uint256 initialRisk
    ) external returns (uint256) {
        require(bytes(name).length > 0, "name required");

        facilityCounter++;
        uint256 id = facilityCounter;

        facilities[id] = Facility({
            name: name,
            hardened: hardened,
            empRiskScore: initialRisk,
            exists: true
        });

        emit FacilityRegistered(id, name, hardened);
        return id;
    }

    function updateFacilityRisk(
        uint256 facilityId,
        string memory newName,
        bool newHardened,
        uint256 newRiskScore
    ) external {
        Facility storage f = facilities[facilityId];
        require(f.exists, "no facility");

        f.name = newName;
        f.hardened = newHardened;
        f.empRiskScore = newRiskScore; // ⚠️ manual override

        emit FacilityUpdated(facilityId, newName, newHardened, newRiskScore);
    }

    function recordEMPEvent(
        uint256 facilityId,
        string memory category,
        uint8 severity
    ) external returns (uint256) {
        require(facilities[facilityId].exists, "no facility");
        require(bytes(category).length > 0, "category required");
        require(severity >= 1 && severity <= 10, "bad severity");

        eventCounter++;
        uint256 eid = eventCounter;

        events[eid] = EMPEvent({
            category: category,
            severity: severity,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        facilityEvents[facilityId].push(eid);

        // naive manual aggregate – but can later be wiped by updateFacilityRisk
        facilities[facilityId].empRiskScore += severity;

        emit EMPEventRecorded(eid, facilityId, category, severity);
        return eid;
    }

    // ⚠️ Anyone can erase an event
    function deleteEMPEvent(uint256 eventId) external {
        require(events[eventId].exists, "no event");
        delete events[eventId];
        emit EMPEventDeleted(eventId);
    }

    function getFacility(uint256 facilityId)
        external
        view
        returns (
            string memory name,
            bool hardened,
            uint256 empRiskScore,
            bool exists
        )
    {
        Facility storage f = facilities[facilityId];
        return (f.name, f.hardened, f.empRiskScore, f.exists);
    }

    function getFacilityEvents(uint256 facilityId) external view returns (uint256[] memory) {
        return facilityEvents[facilityId];
    }
}


/* ============================================================= */
/*  2. ATTACKER – HIDE / FORGE ELECTROMAGNETIC PULSE EXPOSURE    */
/* ============================================================= */

contract ElectromagneticPulseAttacker {
    ElectromagneticPulseV1 public target;
    address public attacker;

    event FacilityRiskHidden(uint256 indexed facilityId, uint256 newScore);
    event EMPEventErased(uint256 indexed eventId);

    constructor(address _target) {
        target = ElectromagneticPulseV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack strategy:
     *  - For a hardened, high-risk facility:
     *     1) Set empRiskScore to 0 (pretend EMP risk is solved).
     *     2) Optionally mark hardened=false to confuse monitoring.
     *     3) Delete high-severity EMP events from history.
     */

    function hideEMPExposure(
        uint256 facilityId,
        string calldata spoofedName
    ) external {
        require(msg.sender == attacker, "not attacker");

        // Set score to 0 and mark as not hardened
        target.updateFacilityRisk(facilityId, spoofedName, false, 0);
        emit FacilityRiskHidden(facilityId, 0);
    }

    function eraseEMPEvent(uint256 eventId) external {
        require(msg.sender == attacker, "not attacker");
        target.deleteEMPEvent(eventId);
        emit EMPEventErased(eventId);
    }
}


/* ============================================================= */
/*   3. SECURE ELECTROMAGNETIC PULSE (EMP) MANAGER – V2 DEFENSE  */
/* ============================================================= */

contract ElectromagneticPulseV2Defense {
    enum Role {
        NONE,
        EMP_ENGINEER,
        ADMIN
    }

    struct Facility {
        string name;
        bool hardened;
        bool exists;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct EMPEvent {
        string category;
        uint8 severity;    // 1–10
        uint64 timestamp;
        uint256 facilityId;
        bool exists;
    }

    address public systemAdmin;
    uint256 public facilityCounter;
    uint256 public eventCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => Facility) public facilities;
    mapping(uint256 => EMPEvent) public events;
    mapping(uint256 => uint256[]) public facilityEvents; // facilityId => event IDs

    event RoleAssigned(address indexed account, Role role);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event FacilityRegistered(uint256 indexed facilityId, string name, bool hardened);
    event FacilityUpdated(uint256 indexed facilityId, string name, bool hardened);
    event EMPEventRecorded(
        uint256 indexed eventId,
        uint256 indexed facilityId,
        string category,
        uint8 severity
    );

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyEngineerOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.EMP_ENGINEER || r == Role.ADMIN, "not engineer/admin");
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

    // ------------- FACILITY MANAGEMENT -------------

    function registerFacility(
        string memory name,
        bool hardened
    ) external onlyAdmin returns (uint256) {
        require(bytes(name).length > 0, "name required");

        facilityCounter++;
        uint256 id = facilityCounter;

        facilities[id] = Facility({
            name: name,
            hardened: hardened,
            exists: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit FacilityRegistered(id, name, hardened);
        return id;
    }

    function updateFacility(
        uint256 facilityId,
        string memory newName,
        bool keepHardened // cannot downgrade hardened→not hardened via this flag
    ) external onlyAdmin {
        Facility storage f = facilities[facilityId];
        require(f.exists, "no facility");
        require(bytes(newName).length > 0, "name required");

        f.name = newName;
        if (f.hardened) {
            // once hardened, stay hardened in this function
            f.hardened = true;
        } else {
            f.hardened = keepHardened;
        }

        f.updatedAt = uint64(block.timestamp);

        emit FacilityUpdated(facilityId, f.name, f.hardened);
    }

    // ------------- EMP EVENT RECORDING -------------

    /*
     *  In V2:
     *   - EMP events are IMMUTABLE: no delete, no overwrite.
     *   - No manual empRiskScore. You derive risk off-chain using events.
     */

    function recordEMPEvent(
        uint256 facilityId,
        string memory category,
        uint8 severity
    ) external onlyEngineerOrAdmin returns (uint256) {
        Facility storage f = facilities[facilityId];
        require(f.exists, "no facility");
        require(bytes(category).length > 0, "category required");
        require(severity >= 1 && severity <= 10, "bad severity");

        eventCounter++;
        uint256 eid = eventCounter;

        events[eid] = EMPEvent({
            category: category,
            severity: severity,
            timestamp: uint64(block.timestamp),
            facilityId: facilityId,
            exists: true
        });

        facilityEvents[facilityId].push(eid);

        emit EMPEventRecorded(eid, facilityId, category, severity);
        return eid;
    }

    // ------------- VIEW HELPERS -------------

    function getFacility(uint256 facilityId)
        external
        view
        returns (
            string memory name,
            bool hardened,
            bool exists,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        Facility storage f = facilities[facilityId];
        return (f.name, f.hardened, f.exists, f.createdAt, f.updatedAt);
    }

    function getFacilityEvents(uint256 facilityId) external view returns (uint256[] memory) {
        return facilityEvents[facilityId];
    }

    function getEMPEvent(uint256 eventId)
        external
        view
        returns (
            string memory category,
            uint8 severity,
            uint64 timestamp,
            uint256 facilityId,
            bool exists
        )
    {
        EMPEvent storage e = events[eventId];
        return (e.category, e.severity, e.timestamp, e.facilityId, e.exists);
    }
}
