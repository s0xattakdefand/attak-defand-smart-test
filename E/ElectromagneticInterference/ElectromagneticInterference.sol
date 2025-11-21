// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTROMAGNETIC INTERFERENCE (EMI) – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *   1) ElectromagneticInterferenceV1          – vulnerable EMI incident registry
 *   2) ElectromagneticInterferenceAttacker    – attacker that hides/forges EMI incidents
 *   3) ElectromagneticInterferenceV2Defense   – secure EMI incident manager with roles
 *
 *  Concept:
 *    - Critical systems (medical devices, avionics, power grid, data centers) can suffer
 *      Electromagnetic Interference (EMI).
 *
 *    - We track:
 *        * Assets (device/site)
 *        * EMI incidents (type, severity, impact)
 *        * Aggregate interferenceScore per asset
 *
 *    V1 BUGS:
 *      - Anyone can:
 *          * register assets and incidents
 *          * overwrite interferenceScore (hide real EMI risk)
 *          * delete incidents (erase evidence)
 *
 *    V2 FIXES:
 *      - Roles: ADMIN, EMI_ENGINEER
 *      - Incidents are immutable (no delete / overwrite)
 *      - “Score” is derived OFF-CHAIN from events (no manual override)
 *      - Assets can’t be silently downgraded from critical
 */


/* ============================================================= */
/*      1. VULNERABLE ELECTROMAGNETIC INTERFERENCE (V1)          */
/* ============================================================= */

contract ElectromagneticInterferenceV1 {
    struct Asset {
        string name;        // e.g. "MRI Scanner #3", "Substation A", "Flight Control Rack"
        bool critical;
        uint256 interferenceScore; // arbitrary manual score
        bool exists;
    }

    struct Incident {
        string emiType;     // "Radiated", "Conducted", "ESD", "Burst", etc.
        uint8 severity;     // 1–10
        string impact;      // free text ("reset", "data loss", "device failure")
        uint64 timestamp;
        bool exists;
    }

    uint256 public assetCounter;
    uint256 public incidentCounter;

    mapping(uint256 => Asset) public assets;
    mapping(uint256 => Incident) public incidents;
    mapping(uint256 => uint256[]) public assetIncidents; // assetId => incident IDs

    event AssetRegistered(uint256 indexed assetId, string name, bool critical);
    event AssetUpdated(uint256 indexed assetId, string name, bool critical, uint256 interferenceScore);
    event IncidentRecorded(
        uint256 indexed incidentId,
        uint256 indexed assetId,
        string emiType,
        uint8 severity,
        string impact
    );
    event IncidentDeleted(uint256 indexed incidentId);

    /*
     * ⚠️ V1 – NO ACCESS CONTROL
     *   - ANY address can:
     *       registerAsset, updateAssetScore, recordIncident, deleteIncident
     *   - Hiding EMI risk is trivial: set interferenceScore=0 and delete serious incidents.
     */

    function registerAsset(
        string memory name,
        bool critical,
        uint256 initialScore
    ) external returns (uint256) {
        require(bytes(name).length > 0, "name required");

        assetCounter++;
        uint256 id = assetCounter;

        assets[id] = Asset({
            name: name,
            critical: critical,
            interferenceScore: initialScore,
            exists: true
        });

        emit AssetRegistered(id, name, critical);
        return id;
    }

    function updateAssetScore(
        uint256 assetId,
        string memory newName,
        bool newCritical,
        uint256 newScore
    ) external {
        Asset storage a = assets[assetId];
        require(a.exists, "no asset");

        a.name = newName;
        a.critical = newCritical;
        a.interferenceScore = newScore; // ⚠️ manual override

        emit AssetUpdated(assetId, newName, newCritical, newScore);
    }

    function recordIncident(
        uint256 assetId,
        string memory emiType,
        uint8 severity,
        string memory impact
    ) external returns (uint256) {
        require(assets[assetId].exists, "no asset");
        require(bytes(emiType).length > 0, "emiType required");
        require(severity >= 1 && severity <= 10, "bad severity");

        incidentCounter++;
        uint256 iid = incidentCounter;

        incidents[iid] = Incident({
            emiType: emiType,
            severity: severity,
            impact: impact,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        assetIncidents[assetId].push(iid);

        // naive manual aggregate – but can later be wiped by updateAssetScore
        assets[assetId].interferenceScore += severity;

        emit IncidentRecorded(iid, assetId, emiType, severity, impact);
        return iid;
    }

    // ⚠️ Anyone can erase an incident
    function deleteIncident(uint256 incidentId) external {
        require(incidents[incidentId].exists, "no incident");
        delete incidents[incidentId];
        emit IncidentDeleted(incidentId);
    }

    function getAsset(uint256 assetId)
        external
        view
        returns (
            string memory name,
            bool critical,
            uint256 interferenceScore,
            bool exists
        )
    {
        Asset storage a = assets[assetId];
        return (a.name, a.critical, a.interferenceScore, a.exists);
    }

    function getAssetIncidents(uint256 assetId) external view returns (uint256[] memory) {
        return assetIncidents[assetId];
    }
}


/* ============================================================= */
/*      2. ATTACKER – HIDE / FORGE ELECTROMAGNETIC INTERFERENCE  */
/* ============================================================= */

contract ElectromagneticInterferenceAttacker {
    ElectromagneticInterferenceV1 public target;
    address public attacker;

    event AssetRiskHidden(uint256 indexed assetId, uint256 newScore);
    event IncidentErased(uint256 indexed incidentId);

    constructor(address _target) {
        target = ElectromagneticInterferenceV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack strategy:
     *  - For a sensitive asset (e.g., avionics or ICU device):
     *     1) Set interferenceScore to 0 (pretend EMI is solved).
     *     2) Optionally mark asset as non-critical.
     *     3) Delete severe incidents from history.
     */

    function hideInterference(
        uint256 assetId,
        string calldata spoofedName
    ) external {
        require(msg.sender == attacker, "not attacker");

        // Set score to 0 and mark non-critical
        target.updateAssetScore(assetId, spoofedName, false, 0);
        emit AssetRiskHidden(assetId, 0);
    }

    function eraseIncident(uint256 incidentId) external {
        require(msg.sender == attacker, "not attacker");
        target.deleteIncident(incidentId);
        emit IncidentErased(incidentId);
    }
}


/* ============================================================= */
/*     3. SECURE ELECTROMAGNETIC INTERFERENCE (V2 DEFENSE)       */
/* ============================================================= */

contract ElectromagneticInterferenceV2Defense {
    enum Role {
        NONE,
        EMI_ENGINEER,
        ADMIN
    }

    struct Asset {
        string name;
        bool critical;
        bool exists;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct EMIIncident {
        string emiType;
        uint8 severity;       // 1–10
        string impact;
        uint64 timestamp;
        uint256 assetId;
        bool exists;
    }

    address public systemAdmin;
    uint256 public assetCounter;
    uint256 public incidentCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => Asset) public assets;
    mapping(uint256 => EMIIncident) public incidents;
    mapping(uint256 => uint256[]) public assetIncidents; // assetId => incident IDs

    event RoleAssigned(address indexed account, Role role);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event AssetRegistered(uint256 indexed assetId, string name, bool critical);
    event AssetUpdated(uint256 indexed assetId, string name, bool critical);
    event EMIIncidentRecorded(
        uint256 indexed incidentId,
        uint256 indexed assetId,
        string emiType,
        uint8 severity,
        string impact
    );

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyEngineerOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.EMI_ENGINEER || r == Role.ADMIN, "not engineer/admin");
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

    // ------------- ASSET MANAGEMENT -------------

    function registerAsset(
        string memory name,
        bool critical
    ) external onlyAdmin returns (uint256) {
        require(bytes(name).length > 0, "name required");

        assetCounter++;
        uint256 id = assetCounter;

        assets[id] = Asset({
            name: name,
            critical: critical,
            exists: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit AssetRegistered(id, name, critical);
        return id;
    }

    function updateAsset(
        uint256 assetId,
        string memory newName,
        bool keepCritical // cannot downgrade critical→non-critical in this function
    ) external onlyAdmin {
        Asset storage a = assets[assetId];
        require(a.exists, "no asset");
        require(bytes(newName).length > 0, "name required");

        a.name = newName;
        if (a.critical) {
            // once critical, stay critical
            a.critical = true;
        } else {
            a.critical = keepCritical;
        }

        a.updatedAt = uint64(block.timestamp);

        emit AssetUpdated(assetId, a.name, a.critical);
    }

    // ------------- INCIDENT RECORDING -------------

    /*
     *  In V2:
     *   - Incidents are IMMUTABLE: no delete, no overwrite.
     *   - No manual interferenceScore. You derive risk off-chain using events.
     */

    function recordEMIIncident(
        uint256 assetId,
        string memory emiType,
        uint8 severity,
        string memory impact
    ) external onlyEngineerOrAdmin returns (uint256) {
        Asset storage a = assets[assetId];
        require(a.exists, "no asset");
        require(bytes(emiType).length > 0, "emiType required");
        require(severity >= 1 && severity <= 10, "bad severity");

        incidentCounter++;
        uint256 iid = incidentCounter;

        incidents[iid] = EMIIncident({
            emiType: emiType,
            severity: severity,
            impact: impact,
            timestamp: uint64(block.timestamp),
            assetId: assetId,
            exists: true
        });

        assetIncidents[assetId].push(iid);

        emit EMIIncidentRecorded(iid, assetId, emiType, severity, impact);
        return iid;
    }

    // ------------- VIEW HELPERS -------------

    function getAsset(uint256 assetId)
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
        Asset storage a = assets[assetId];
        return (a.name, a.critical, a.exists, a.createdAt, a.updatedAt);
    }

    function getAssetIncidents(uint256 assetId) external view returns (uint256[] memory) {
        return assetIncidents[assetId];
    }

    function getIncident(uint256 incidentId)
        external
        view
        returns (
            string memory emiType,
            uint8 severity,
            string memory impact,
            uint64 timestamp,
            uint256 assetId,
            bool exists
        )
    {
        EMIIncident storage e = incidents[incidentId];
        return (e.emiType, e.severity, e.impact, e.timestamp, e.assetId, e.exists);
    }
}
