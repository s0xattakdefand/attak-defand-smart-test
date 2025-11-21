// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTROMAGNETIC – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *  1) ElectromagneticV1        – vulnerable EM field safety manager (zones + exposure)
 *  2) ElectromagneticAttacker  – attacker that disables safety limits
 *  3) ElectromagneticV2Defense – hardened EM safety manager with roles + validation
 *
 *  Concept:
 *    - You have zones (e.g., data center rooms, antenna areas) with EM safe limits.
 *    - Devices report their field strength in each zone.
 *
 *    V1 BUGS:
 *      - Anyone can change safe limits for any zone (no access control).
 *      - Anyone can mark a critical zone as non-critical.
 *      - Exposure recording ignores safety threshold (no enforcement).
 *
 *    V2 FIXES:
 *      - Only admin / safety officers can define or modify zones.
 *      - Hard check: exposure cannot exceed safe limit (or logs violation).
 *      - Critical flag cannot be removed without admin.
 */


/* ============================================================= */
/*          1. VULNERABLE ELECTROMAGNETIC MANAGER (V1)           */
/* ============================================================= */

contract ElectromagneticV1 {
    struct Zone {
        string label;        // e.g., "Server Room A", "Antenna Roof"
        uint256 safeLimit;   // max allowed field strength (e.g., microTesla)
        bool critical;       // true if must never be disabled in practice
        bool exists;
    }

    uint256 public zoneCounter;
    mapping(uint256 => Zone) public zones;
    mapping(uint256 => mapping(address => uint256)) public lastExposure; // zoneId => device => fieldStrength

    event ZoneCreated(uint256 indexed zoneId, string label, uint256 safeLimit, bool critical);
    event ZoneUpdated(uint256 indexed zoneId, uint256 safeLimit, bool critical);
    event ExposureReported(uint256 indexed zoneId, address indexed device, uint256 fieldStrength);

    /*
     *  ⚠️ VULNERABILITY:
     *    - Anyone can create zones.
     *    - Anyone can update *any* zone's safety limit and critical flag.
     */

    function createZone(
        string memory label,
        uint256 safeLimit,
        bool critical
    ) external returns (uint256) {
        require(bytes(label).length > 0, "label required");
        require(safeLimit > 0, "safeLimit zero");

        zoneCounter++;
        uint256 id = zoneCounter;

        zones[id] = Zone({
            label: label,
            safeLimit: safeLimit,
            critical: critical,
            exists: true
        });

        emit ZoneCreated(id, label, safeLimit, critical);
        return id;
    }

    // ⚠️ Anyone can modify safety limits and critical flag.
    function updateZone(
        uint256 zoneId,
        uint256 newSafeLimit,
        bool newCritical
    ) external {
        Zone storage z = zones[zoneId];
        require(z.exists, "zone missing");
        require(newSafeLimit > 0, "safeLimit zero");

        z.safeLimit = newSafeLimit;
        z.critical = newCritical;

        emit ZoneUpdated(zoneId, newSafeLimit, newCritical);
    }

    /*
     *  ⚠️ VULNERABILITY:
     *     - We *do not* enforce safeLimit here.
     *     - Off-chain systems might read lastExposure and assume it's safe
     *       as long as `fieldStrength <= safeLimit`, but attacker can first
     *       raise safeLimit to something huge.
     */
    function reportExposure(uint256 zoneId, uint256 fieldStrength) external {
        Zone storage z = zones[zoneId];
        require(z.exists, "zone missing");
        require(fieldStrength > 0, "zero exposure");

        lastExposure[zoneId][msg.sender] = fieldStrength;

        emit ExposureReported(zoneId, msg.sender, fieldStrength);
    }
}


/* ============================================================= */
/*                    2. ATTACKER CONTRACT                       */
/* ============================================================= */

contract ElectromagneticAttacker {
    ElectromagneticV1 public target;
    address public attacker;

    event LimitRelaxed(uint256 indexed zoneId, uint256 newLimit, bool newCriticalFlag);
    event UnsafeExposureSent(uint256 indexed zoneId, address indexed device, uint256 fieldStrength);

    constructor(address _target) {
        target = ElectromagneticV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack idea:
     *  1. Pick a victim zone with low safeLimit and critical = true.
     *  2. Call updateZone(zoneId, VERY_HIGH_LIMIT, false) to effectively disable safety.
     *  3. Call reportExposure(zoneId, EXTREME_FIELD_STRENGTH) to make logs look "safe".
     */

    function relaxLimitAndReport(
        uint256 zoneId,
        uint256 fakeSafeLimit,
        uint256 dangerousField
    ) external {
        require(msg.sender == attacker, "not attacker");

        // Step 1: disable / relax safety limit
        target.updateZone(zoneId, fakeSafeLimit, false);
        emit LimitRelaxed(zoneId, fakeSafeLimit, false);

        // Step 2: report a dangerous exposure that appears "inside" the new fake limit
        target.reportExposure(zoneId, dangerousField);
        emit UnsafeExposureSent(zoneId, attacker, dangerousField);
    }
}


/* ============================================================= */
/*         3. SECURE ELECTROMAGNETIC MANAGER (V2 DEFENSE)        */
/* ============================================================= */

contract ElectromagneticV2Defense {
    struct Zone {
        string label;
        uint256 safeLimit;
        bool critical;
        bool exists;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct ExposureLog {
        uint256 fieldStrength;
        uint64 timestamp;
        bool violation;
    }

    address public systemAdmin;
    mapping(address => bool) public safetyOfficer;

    uint256 public zoneCounter;
    mapping(uint256 => Zone) public zones;
    mapping(uint256 => mapping(address => ExposureLog)) public exposureLogs;

    event ZoneCreated(
        uint256 indexed zoneId,
        string label,
        uint256 safeLimit,
        bool critical,
        address indexed by
    );

    event ZoneUpdated(
        uint256 indexed zoneId,
        uint256 safeLimit,
        bool critical,
        address indexed by
    );

    event ExposureRecorded(
        uint256 indexed zoneId,
        address indexed device,
        uint256 fieldStrength,
        bool violation
    );

    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event SafetyOfficerSet(address indexed officer, bool enabled);

    modifier onlyAdmin() {
        require(msg.sender == systemAdmin, "not admin");
        _;
    }

    modifier onlyAdminOrOfficer() {
        require(
            msg.sender == systemAdmin || safetyOfficer[msg.sender],
            "not admin/officer"
        );
        _;
    }

    constructor() {
        systemAdmin = msg.sender;
    }

    function changeAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "zero");
        address old = systemAdmin;
        systemAdmin = newAdmin;
        emit AdminChanged(old, newAdmin);
    }

    function setSafetyOfficer(address officer, bool enabled) external onlyAdmin {
        require(officer != address(0), "zero");
        safetyOfficer[officer] = enabled;
        emit SafetyOfficerSet(officer, enabled);
    }

    // ---------------- ZONE MANAGEMENT (SECURE) -----------------

    function createZone(
        string memory label,
        uint256 safeLimit,
        bool critical
    ) external onlyAdminOrOfficer returns (uint256) {
        require(bytes(label).length > 0, "label required");
        require(safeLimit > 0, "safeLimit zero");

        zoneCounter++;
        uint256 id = zoneCounter;

        zones[id] = Zone({
            label: label,
            safeLimit: safeLimit,
            critical: critical,
            exists: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit ZoneCreated(id, label, safeLimit, critical, msg.sender);
        return id;
    }

    function updateZone(
        uint256 zoneId,
        uint256 newSafeLimit,
        bool keepCritical  // true means keep critical, cannot turn off if already critical
    ) external onlyAdminOrOfficer {
        Zone storage z = zones[zoneId];
        require(z.exists, "zone missing");
        require(newSafeLimit > 0, "safeLimit zero");

        z.safeLimit = newSafeLimit;

        // If zone is already critical, we DO NOT allow turning it off via this function
        if (z.critical) {
            z.critical = true;
        } else {
            z.critical = keepCritical;
        }

        z.updatedAt = uint64(block.timestamp);

        emit ZoneUpdated(zoneId, z.safeLimit, z.critical, msg.sender);
    }

    // ---------------- EXPOSURE REPORTING (SECURE) --------------

    /*
     *  Hard rule:
     *    - If fieldStrength > safeLimit → violation = true
     *    - We *still* record it, but mark it as violation so monitoring/off-chain
     *      systems can take action (shut down, alert, etc.).
     *
     *  No one can silently bypass safeLimit by changing it first without admin/officer rights.
     */
    function reportExposure(uint256 zoneId, uint256 fieldStrength) external {
        Zone storage z = zones[zoneId];
        require(z.exists, "zone missing");
        require(fieldStrength > 0, "zero exposure");

        bool violated = fieldStrength > z.safeLimit;

        exposureLogs[zoneId][msg.sender] = ExposureLog({
            fieldStrength: fieldStrength,
            timestamp: uint64(block.timestamp),
            violation: violated
        });

        emit ExposureRecorded(zoneId, msg.sender, fieldStrength, violated);
    }

    function getExposure(
        uint256 zoneId,
        address device
    )
        external
        view
        returns (
            uint256 fieldStrength,
            uint64 timestamp,
            bool violation
        )
    {
        ExposureLog storage log = exposureLogs[zoneId][device];
        return (log.fieldStrength, log.timestamp, log.violation);
    }
}
