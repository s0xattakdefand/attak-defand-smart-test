// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTRONIC CONTROL UNIT (ECU) – SMART CONTRACT LAB
 *
 *  1) ElectronicControlUnitV1
 *       - Vulnerable ECU registry and diagnostics
 *  2) ElectronicControlUnitAttacker
 *       - Attack: spoof firmware, downgrade safety, hide errors
 *  3) ElectronicControlUnitV2Defense
 *       - Secure ECU registry: roles, immutable diagnostics, version control
 *
 *  Concept:
 *    - Each ECU is registered (VIN/device ID, model, firmware version).
 *    - Diagnostics are logged as DTC codes (P0xxx style) with severity.
 *
 *    V1 BUGS:
 *      - Anyone can:
 *          * register fake ECUs
 *          * change firmwareVersion and safetyCritical flag
 *          * delete diagnostic reports (erase evidence)
 *
 *    V2 FIXES:
 *      - Roles: ADMIN, OEM, MECHANIC, AUDITOR
 *      - Only OEM/ADMIN can register ECUs and update firmware
 *      - Only MECHANIC/OEM can add diagnostics
 *      - No delete for diagnostics; logs are immutable
 *      - Firmware version is strictly monotonic (no downgrades)
 */


/* ============================================================= */
/*           1. VULNERABLE ELECTRONIC CONTROL UNIT (V1)          */
/* ============================================================= */

contract ElectronicControlUnitV1 {
    struct ECU {
        string vinOrId;        // Vehicle VIN or ECU unique ID
        string model;          // ECU model
        string firmwareVersion;
        bool safetyCritical;   // true if part of brake/steering/etc.
        bool exists;
    }

    struct DiagnosticReport {
        uint256 ecuId;
        string dtcCode;        // e.g., "P0420"
        uint8 severity;        // 1–10
        uint64 timestamp;
        bool exists;
    }

    uint256 public ecuCounter;
    uint256 public reportCounter;

    mapping(uint256 => ECU) public ecus;
    mapping(uint256 => DiagnosticReport) public reports;
    mapping(uint256 => uint256[]) public ecuReports; // ecuId => report IDs

    event ECURegistered(
        uint256 indexed ecuId,
        string vinOrId,
        string model,
        string firmwareVersion,
        bool safetyCritical
    );

    event ECUUpdated(
        uint256 indexed ecuId,
        string firmwareVersion,
        bool safetyCritical
    );

    event DiagnosticLogged(
        uint256 indexed reportId,
        uint256 indexed ecuId,
        string dtcCode,
        uint8 severity
    );

    event DiagnosticDeleted(uint256 indexed reportId);

    /*
     * ⚠️ V1 – NO ACCESS CONTROL
     *   - ANY address can:
     *       registerECU, updateECU, logDiagnostic, deleteDiagnostic
     *   - Attacker can:
     *       spoof firmwareVersion, mark safetyCritical=false, delete bad diagnostics.
     */

    function registerECU(
        string memory vinOrId,
        string memory model,
        string memory firmwareVersion,
        bool safetyCritical
    ) external returns (uint256) {
        require(bytes(vinOrId).length > 0, "vin/id required");
        require(bytes(model).length > 0, "model required");

        ecuCounter++;
        uint256 id = ecuCounter;

        ecus[id] = ECU({
            vinOrId: vinOrId,
            model: model,
            firmwareVersion: firmwareVersion,
            safetyCritical: safetyCritical,
            exists: true
        });

        emit ECURegistered(id, vinOrId, model, firmwareVersion, safetyCritical);
        return id;
    }

    // ⚠️ Anyone can change firmware & safety flag
    function updateECU(
        uint256 ecuId,
        string memory newFirmwareVersion,
        bool newSafetyCritical
    ) external {
        ECU storage e = ecus[ecuId];
        require(e.exists, "no ecu");

        e.firmwareVersion = newFirmwareVersion;
        e.safetyCritical = newSafetyCritical;

        emit ECUUpdated(ecuId, newFirmwareVersion, newSafetyCritical);
    }

    // Log diagnostic trouble code
    function logDiagnostic(
        uint256 ecuId,
        string memory dtcCode,
        uint8 severity
    ) external returns (uint256) {
        ECU storage e = ecus[ecuId];
        require(e.exists, "no ecu");
        require(bytes(dtcCode).length > 0, "dtc required");
        require(severity >= 1 && severity <= 10, "bad severity");

        reportCounter++;
        uint256 rid = reportCounter;

        reports[rid] = DiagnosticReport({
            ecuId: ecuId,
            dtcCode: dtcCode,
            severity: severity,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        ecuReports[ecuId].push(rid);

        emit DiagnosticLogged(rid, ecuId, dtcCode, severity);
        return rid;
    }

    // ⚠️ Anyone can erase diagnostics
    function deleteDiagnostic(uint256 reportId) external {
        require(reports[reportId].exists, "no report");
        delete reports[reportId];
        emit DiagnosticDeleted(reportId);
    }

    function getECU(uint256 ecuId)
        external
        view
        returns (
            string memory vinOrId,
            string memory model,
            string memory firmwareVersion,
            bool safetyCritical,
            bool exists
        )
    {
        ECU storage e = ecus[ecuId];
        return (e.vinOrId, e.model, e.firmwareVersion, e.safetyCritical, e.exists);
    }

    function getDiagnostic(uint256 reportId)
        external
        view
        returns (
            uint256 ecuId,
            string memory dtcCode,
            uint8 severity,
            uint64 timestamp,
            bool exists
        )
    {
        DiagnosticReport storage r = reports[reportId];
        return (r.ecuId, r.dtcCode, r.severity, r.timestamp, r.exists);
    }

    function getECUReports(uint256 ecuId) external view returns (uint256[] memory) {
        return ecuReports[ecuId];
    }
}


/* ============================================================= */
/*     2. ATTACKER – SPOOF FIRMWARE & HIDE ECU DIAGNOSTICS       */
/* ============================================================= */

contract ElectronicControlUnitAttacker {
    ElectronicControlUnitV1 public target;
    address public attacker;

    event FirmwareSpoofed(uint256 indexed ecuId, string newFirmwareVersion, bool safetyCritical);
    event DiagnosticErased(uint256 indexed reportId);

    constructor(address _target) {
        target = ElectronicControlUnitV1(_target);
        attacker = msg.sender;
    }

    /*
     *  Attack pattern:
     *    - For a safety-critical ECU with bad diagnostics:
     *        1) Change firmwareVersion to "clean"/fake version.
     *        2) Flip safetyCritical to false.
     *        3) Delete all severe diagnostics.
     */

    function spoofFirmware(
        uint256 ecuId,
        string calldata fakeFirmwareVersion,
        bool newSafetyCritical
    ) external {
        require(msg.sender == attacker, "not attacker");

        target.updateECU(ecuId, fakeFirmwareVersion, newSafetyCritical);
        emit FirmwareSpoofed(ecuId, fakeFirmwareVersion, newSafetyCritical);
    }

    function eraseDiagnostic(uint256 reportId) external {
        require(msg.sender == attacker, "not attacker");

        target.deleteDiagnostic(reportId);
        emit DiagnosticErased(reportId);
    }
}


/* ============================================================= */
/*   3. SECURE ELECTRONIC CONTROL UNIT – V2 DEFENSE              */
/* ============================================================= */

contract ElectronicControlUnitV2Defense {
    enum Role {
        NONE,
        MECHANIC,
        OEM,
        AUDITOR,
        ADMIN
    }

    struct ECU {
        string vinOrId;
        string model;
        string firmwareVersion;
        bool safetyCritical;
        bool locked;          // when locked, no more firmware changes
        bool exists;
        uint64 createdAt;
        uint64 updatedAt;
        uint64 firmwareVersionNumber; // monotonic incremental version
    }

    struct DiagnosticReport {
        uint256 ecuId;
        string dtcCode;
        uint8 severity;
        address reportedBy;
        uint64 timestamp;
        bool exists;
    }

    address public systemAdmin;
    uint256 public ecuCounter;
    uint256 public reportCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => ECU) public ecus;
    mapping(uint256 => DiagnosticReport) public reports;
    mapping(uint256 => uint256[]) public ecuReports;

    event RoleAssigned(address indexed account, Role role);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    event ECURegistered(
        uint256 indexed ecuId,
        string vinOrId,
        string model,
        string firmwareVersion,
        bool safetyCritical
    );

    event ECUFirmwareUpdated(
        uint256 indexed ecuId,
        string firmwareVersion,
        uint64 versionNumber,
        address updatedBy
    );

    event ECUSafetyFlagUpdated(
        uint256 indexed ecuId,
        bool safetyCritical,
        address updatedBy
    );

    event ECULocked(
        uint256 indexed ecuId,
        address lockedBy
    );

    event DiagnosticLogged(
        uint256 indexed reportId,
        uint256 indexed ecuId,
        string dtcCode,
        uint8 severity,
        address reportedBy
    );

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyOEMOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.OEM || r == Role.ADMIN, "not oem/admin");
        _;
    }

    modifier onlyMechanicOrOEMOrAdmin() {
        Role r = roles[msg.sender];
        require(
            r == Role.MECHANIC || r == Role.OEM || r == Role.ADMIN,
            "not mechanic/oem/admin"
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

    // ---------------- ECU MANAGEMENT ----------------

    function registerECU(
        string memory vinOrId,
        string memory model,
        string memory firmwareVersion,
        bool safetyCritical
    ) external onlyOEMOrAdmin returns (uint256) {
        require(bytes(vinOrId).length > 0, "vin/id required");
        require(bytes(model).length > 0, "model required");

        ecuCounter++;
        uint256 id = ecuCounter;

        ecus[id] = ECU({
            vinOrId: vinOrId,
            model: model,
            firmwareVersion: firmwareVersion,
            safetyCritical: safetyCritical,
            locked: false,
            exists: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp),
            firmwareVersionNumber: 1
        });

        emit ECURegistered(id, vinOrId, model, firmwareVersion, safetyCritical);
        return id;
    }

    /*
     * Firmware updates:
     *   - Only OEM/ADMIN
     *   - Cannot update if ECU.locked == true
     *   - Version number is strictly incremented (monotonic)
     */
    function updateFirmware(
        uint256 ecuId,
        string memory newFirmwareVersion
    ) external onlyOEMOrAdmin {
        ECU storage e = ecus[ecuId];
        require(e.exists, "no ecu");
        require(!e.locked, "ecu locked");
        require(bytes(newFirmwareVersion).length > 0, "fw required");

        e.firmwareVersion = newFirmwareVersion;
        e.firmwareVersionNumber += 1;
        e.updatedAt = uint64(block.timestamp);

        emit ECUFirmwareUpdated(
            ecuId,
            newFirmwareVersion,
            e.firmwareVersionNumber,
            msg.sender
        );
    }

    /*
     * Safety flag changes:
     *   - Only ADMIN can toggle safetyCritical
     */
    function setSafetyCritical(
        uint256 ecuId,
        bool safetyCritical
    ) external onlyAdmin {
        ECU storage e = ecus[ecuId];
        require(e.exists, "no ecu");

        e.safetyCritical = safetyCritical;
        e.updatedAt = uint64(block.timestamp);

        emit ECUSafetyFlagUpdated(ecuId, safetyCritical, msg.sender);
    }

    /*
     * Lock ECU (no more firmware changes):
     *   - Only ADMIN can lock
     */
    function lockECU(uint256 ecuId) external onlyAdmin {
        ECU storage e = ecus[ecuId];
        require(e.exists, "no ecu");
        require(!e.locked, "already locked");

        e.locked = true;
        e.updatedAt = uint64(block.timestamp);

        emit ECULocked(ecuId, msg.sender);
    }

    // ---------------- DIAGNOSTICS ----------------

    /*
     * Log diagnostics:
     *   - Only MECHANIC, OEM, or ADMIN can log DTCs
     *   - No delete function (immutable history)
     */
    function logDiagnostic(
        uint256 ecuId,
        string memory dtcCode,
        uint8 severity
    ) external onlyMechanicOrOEMOrAdmin returns (uint256) {
        ECU storage e = ecus[ecuId];
        require(e.exists, "no ecu");
        require(bytes(dtcCode).length > 0, "dtc required");
        require(severity >= 1 && severity <= 10, "bad severity");

        reportCounter++;
        uint256 rid = reportCounter;

        reports[rid] = DiagnosticReport({
            ecuId: ecuId,
            dtcCode: dtcCode,
            severity: severity,
            reportedBy: msg.sender,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        ecuReports[ecuId].push(rid);

        emit DiagnosticLogged(rid, ecuId, dtcCode, severity, msg.sender);
        return rid;
    }

    // ---------------- VIEW HELPERS ----------------

    function getECU(uint256 ecuId)
        external
        view
        returns (
            string memory vinOrId,
            string memory model,
            string memory firmwareVersion,
            bool safetyCritical,
            bool locked,
            bool exists,
            uint64 createdAt,
            uint64 updatedAt,
            uint64 firmwareVersionNumber
        )
    {
        ECU storage e = ecus[ecuId];
        return (
            e.vinOrId,
            e.model,
            e.firmwareVersion,
            e.safetyCritical,
            e.locked,
            e.exists,
            e.createdAt,
            e.updatedAt,
            e.firmwareVersionNumber
        );
    }

    function getDiagnostic(uint256 reportId)
        external
        view
        returns (
            uint256 ecuId,
            string memory dtcCode,
            uint8 severity,
            address reportedBy,
            uint64 timestamp,
            bool exists
        )
    {
        DiagnosticReport storage r = reports[reportId];
        return (
            r.ecuId,
            r.dtcCode,
            r.severity,
            r.reportedBy,
            r.timestamp,
            r.exists
        );
    }

    function getECUReports(uint256 ecuId) external view returns (uint256[] memory) {
        return ecuReports[ecuId];
    }
}
