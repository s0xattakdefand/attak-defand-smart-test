// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTROMAGNETIC COMPATIBILITY (EMC) – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *  1) ElectromagneticCompatibilityV1          – vulnerable EMC device compatibility registry
 *  2) ElectromagneticCompatibilityAttacker    – attacker that fakes compliance & deletes others
 *  3) ElectromagneticCompatibilityV2Defense   – secure EMC lab with roles + immutable test history
 *
 *  Concept:
 *    - Devices must be tested for EMC (electromagnetic compatibility) vs a standard (e.g. CISPR, IEC).
 *    - Registry tracks whether a device is "compatible" (pass) or not.
 *
 *    V1 BUGS:
 *      - Anyone can mark ANY device as compatible.
 *      - Anyone can change the standard to something fake.
 *      - Anyone can delete devices (erase evidence).
 *
 *    V2 FIXES:
 *      - Roles: ADMIN, LAB_ENGINEER, MANUFACTURER
 *      - Only ADMIN can register devices & set required standard.
 *      - Only LAB_ENGINEER can record test results.
 *      - Compatibility is derived from tests; you cannot just flip a boolean.
 *      - No hard delete; only deprecate (soft delete) while keeping history.
 */


/* ============================================================= */
/*          1. VULNERABLE ELECTROMAGNETIC COMPATIBILITY V1       */
/* ============================================================= */

contract ElectromagneticCompatibilityV1 {
    struct Device {
        string name;
        string standard;     // e.g., "IEC 61000-4-2", "CISPR 32"
        bool compatible;     // TRUE means EMC compliant
        bool exists;
    }

    uint256 public deviceCounter;
    mapping(uint256 => Device) public devices;

    event DeviceRegistered(uint256 indexed id, string name, string standard);
    event DeviceUpdated(uint256 indexed id, string standard, bool compatible);
    event DeviceDeleted(uint256 indexed id);

    /*
     * ⚠️ VULNERABILITIES:
     *  - No access control anywhere.
     *  - Anyone can:
     *     * register fake devices,
     *     * mark any device as compatible,
     *     * change required standard to nonsense,
     *     * delete devices (removing audit trail).
     */

    function registerDevice(string memory name, string memory standard)
        external
        returns (uint256)
    {
        require(bytes(name).length > 0, "name required");
        require(bytes(standard).length > 0, "standard required");

        deviceCounter++;
        uint256 id = deviceCounter;

        devices[id] = Device({
            name: name,
            standard: standard,
            compatible: false,
            exists: true
        });

        emit DeviceRegistered(id, name, standard);
        return id;
    }

    function updateDevice(
        uint256 id,
        string memory newStandard,
        bool newCompatible
    ) external {
        Device storage d = devices[id];
        require(d.exists, "no device");

        d.standard = newStandard;
        d.compatible = newCompatible;

        emit DeviceUpdated(id, newStandard, newCompatible);
    }

    function deleteDevice(uint256 id) external {
        require(devices[id].exists, "no device");
        delete devices[id];
        emit DeviceDeleted(id);
    }
}


/* ============================================================= */
/*                   2. ATTACKER CONTRACT                        */
/* ============================================================= */

contract ElectromagneticCompatibilityAttacker {
    ElectromagneticCompatibilityV1 public target;
    address public attacker;

    event FakeCompatible(uint256 indexed id);
    event DeviceErased(uint256 indexed id);

    constructor(address _target) {
        target = ElectromagneticCompatibilityV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack scenario:
     *  - Victim registers devices & expects only lab to mark compatibility.
     *  - Attacker:
     *      1) Changes standard to something weak/fake.
     *      2) Marks device as compatible = true.
     *      3) Optionally deletes other devices to hide non-compliant ones.
     */

    function fakePass(uint256 deviceId, string calldata fakeStandard) external {
        require(msg.sender == attacker, "not attacker");

        // Mark device as "compatible" with fake standard
        target.updateDevice(deviceId, fakeStandard, true);
        emit FakeCompatible(deviceId);
    }

    function eraseDevice(uint256 deviceId) external {
        require(msg.sender == attacker, "not attacker");
        target.deleteDevice(deviceId);
        emit DeviceErased(deviceId);
    }
}


/* ============================================================= */
/*    3. SECURE ELECTROMAGNETIC COMPATIBILITY LAB (V2 DEFENSE)   */
/* ============================================================= */

contract ElectromagneticCompatibilityV2Defense {
    enum Role {
        NONE,
        MANUFACTURER,
        LAB_ENGINEER,
        ADMIN
    }

    struct Device {
        string name;
        string requiredStandard;   // required EMC standard
        address manufacturer;
        bool exists;
        bool deprecated;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct TestResult {
        bool tested;
        bool passed;
        uint64 timestamp;
        string labNote;
        address engineer;
    }

    address public systemAdmin;
    uint256 public deviceCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => Device) public devices;
    mapping(uint256 => TestResult) public latestTest;

    event RoleAssigned(address indexed account, Role role);
    event DeviceRegistered(
        uint256 indexed id,
        string name,
        string requiredStandard,
        address manufacturer
    );
    event DeviceDeprecated(uint256 indexed id, address indexed by);
    event TestRecorded(
        uint256 indexed id,
        bool passed,
        address indexed engineer,
        string labNote
    );
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyEngineer() {
        require(roles[msg.sender] == Role.LAB_ENGINEER, "not lab engineer");
        _;
    }

    modifier onlyManufacturer() {
        require(roles[msg.sender] == Role.MANUFACTURER, "not manufacturer");
        _;
    }

    constructor() {
        systemAdmin = msg.sender;
        roles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    // -------------------- ROLE MANAGEMENT ----------------------

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

    // -------------------- DEVICE REGISTRATION ------------------

    /*
     *  Device lifecycle:
     *    - ADMIN registers device and defines required EMC standard.
     *    - Manufacturer identity is recorded.
     *    - Only LAB_ENGINEER can record pass/fail.
     *    - Device can be deprecated (soft delete) but data remains.
     */

    function registerDevice(
        string memory name,
        string memory requiredStandard,
        address manufacturer
    )
        external
        onlyAdmin
        returns (uint256)
    {
        require(bytes(name).length > 0, "name required");
        require(bytes(requiredStandard).length > 0, "standard required");
        require(manufacturer != address(0), "invalid manufacturer");

        deviceCounter++;
        uint256 id = deviceCounter;

        devices[id] = Device({
            name: name,
            requiredStandard: requiredStandard,
            manufacturer: manufacturer,
            exists: true,
            deprecated: false,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit DeviceRegistered(id, name, requiredStandard, manufacturer);
        return id;
    }

    function deprecateDevice(uint256 id) external onlyAdmin {
        Device storage d = devices[id];
        require(d.exists, "no device");
        require(!d.deprecated, "already deprecated");

        d.deprecated = true;
        d.updatedAt = uint64(block.timestamp);

        emit DeviceDeprecated(id, msg.sender);
    }

    // -------------------- EMC TESTING --------------------------

    /*
     * Only LAB_ENGINEER can record tests.
     * Compatibility is derived: device is "compatible" iff last test exists and passed == true.
     */

    function recordTestResult(
        uint256 id,
        bool passed,
        string calldata labNote
    ) external onlyEngineer {
        Device storage d = devices[id];
        require(d.exists, "no device");
        require(!d.deprecated, "device deprecated");

        latestTest[id] = TestResult({
            tested: true,
            passed: passed,
            timestamp: uint64(block.timestamp),
            labNote: labNote,
            engineer: msg.sender
        });

        d.updatedAt = uint64(block.timestamp);

        emit TestRecorded(id, passed, msg.sender, labNote);
    }

    // -------------------- VIEW HELPERS -------------------------

    function isCompatible(uint256 id) external view returns (bool) {
        Device storage d = devices[id];
        if (!d.exists || d.deprecated) return false;
        TestResult storage t = latestTest[id];
        return t.tested && t.passed;
    }

    function getDevice(uint256 id)
        external
        view
        returns (
            string memory name,
            string memory requiredStandard,
            address manufacturer,
            bool exists,
            bool deprecated,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        Device storage d = devices[id];
        return (
            d.name,
            d.requiredStandard,
            d.manufacturer,
            d.exists,
            d.deprecated,
            d.createdAt,
            d.updatedAt
        );
    }

    function getLatestTest(uint256 id)
        external
        view
        returns (
            bool tested,
            bool passed,
            uint64 timestamp,
            string memory labNote,
            address engineer
        )
    {
        TestResult storage t = latestTest[id];
        return (t.tested, t.passed, t.timestamp, t.labNote, t.engineer);
    }
}
