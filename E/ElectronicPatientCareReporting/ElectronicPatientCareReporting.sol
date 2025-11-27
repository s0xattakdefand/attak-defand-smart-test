// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
==============================================================
 ELECTRONIC PATIENT CARE REPORTING (ePCR) – SMART CONTRACT LAB
==============================================================

This file contains:

1) ElectronicPatientCareReportingV1 (insecure)
   - On-chain patient care records
   - Anyone can create, edit, delete records
   - No integrity, no role checks, no audit guarantees

2) ElectronicPatientCareReportingAttacker
   - Forges patient reports
   - Tamper with existing records
   - Deletes records to hide malpractice

3) ElectronicPatientCareReportingV2Defense
   - Role-based (EMT, SUPERVISOR, MEDICAL_DIRECTOR, AUDITOR, ADMIN)
   - Patient records are hash-anchored
   - Soft-delete / archive only (no hard delete)
   - Immutable audit trail
   - Off-chain encrypted data via URI (not raw PHI on-chain)
*/


/* ========================================================= */
/* 1. INSECURE ePCR SYSTEM (V1)                              */
/* ========================================================= */

contract ElectronicPatientCareReportingV1 {
    struct EPCR {
        string patientId;         // e.g. hospital MRN or hashed
        string incidentId;        // EMS incident number
        string chiefComplaint;
        string assessment;        // exam findings
        string treatment;         // meds / procedures
        uint64 timestamp;
        address recordedBy;
        bool locked;              // intended to prevent edits (but not enforced properly)
        bool exists;
    }

    uint256 public recordCounter;
    mapping(uint256 => EPCR) public records;

    event RecordCreated(uint256 indexed recordId, string patientId, string incidentId);
    event RecordUpdated(uint256 indexed recordId);
    event RecordDeleted(uint256 indexed recordId);
    event RecordLocked(uint256 indexed recordId, bool locked);

    /*
     * ⚠ V1 Vulnerabilities:
     *   - ANY address can:
     *       * createRecord
     *       * updateRecord
     *       * deleteRecord
     *       * lock/unlock any record
     *   - No integrity hash
     *   - Raw PHI stored on-chain (bad in real life)
     */

    function createRecord(
        string memory patientId,
        string memory incidentId,
        string memory chiefComplaint,
        string memory assessment,
        string memory treatment
    ) external returns (uint256) {
        recordCounter++;
        uint256 id = recordCounter;

        records[id] = EPCR({
            patientId: patientId,
            incidentId: incidentId,
            chiefComplaint: chiefComplaint,
            assessment: assessment,
            treatment: treatment,
            timestamp: uint64(block.timestamp),
            recordedBy: msg.sender,
            locked: false,
            exists: true
        });

        emit RecordCreated(id, patientId, incidentId);
        return id;
    }

    // ⚠ Anyone can update anything, including locked records
    function updateRecord(
        uint256 recordId,
        string memory chiefComplaint,
        string memory assessment,
        string memory treatment
    ) external {
        EPCR storage r = records[recordId];
        require(r.exists, "no record");

        r.chiefComplaint = chiefComplaint;
        r.assessment = assessment;
        r.treatment = treatment;
        r.timestamp = uint64(block.timestamp);

        emit RecordUpdated(recordId);
    }

    // ⚠ Anyone can toggle locked flag
    function setLocked(uint256 recordId, bool lockedFlag) external {
        EPCR storage r = records[recordId];
        require(r.exists, "no record");
        r.locked = lockedFlag;
        emit RecordLocked(recordId, lockedFlag);
    }

    // ⚠ Anyone can erase entire record
    function deleteRecord(uint256 recordId) external {
        require(records[recordId].exists, "no record");
        delete records[recordId];
        emit RecordDeleted(recordId);
    }

    function getRecord(uint256 recordId)
        external
        view
        returns (
            string memory patientId,
            string memory incidentId,
            string memory chiefComplaint,
            string memory assessment,
            string memory treatment,
            uint64 timestamp,
            address recordedBy,
            bool locked,
            bool exists
        )
    {
        EPCR storage r = records[recordId];
        return (
            r.patientId,
            r.incidentId,
            r.chiefComplaint,
            r.assessment,
            r.treatment,
            r.timestamp,
            r.recordedBy,
            r.locked,
            r.exists
        );
    }
}


/* ========================================================= */
/* 2. ATTACKER – TAMPER & DELETE ePCR                         */
/* ========================================================= */

contract ElectronicPatientCareReportingAttacker {
    ElectronicPatientCareReportingV1 public target;
    address public attacker;

    event FakeRecordCreated(uint256 indexed recordId);
    event RecordTampered(uint256 indexed recordId);
    event RecordErased(uint256 indexed recordId);

    constructor(address _target) {
        target = ElectronicPatientCareReportingV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack examples:
     *  - Create fake records
     *  - Modify existing treatment/assessment
     *  - Delete adverse outcome records
     */

    function createFakeRecord(
        string calldata patientId,
        string calldata incidentId,
        string calldata chiefComplaint,
        string calldata assessment,
        string calldata treatment
    ) external returns (uint256) {
        require(msg.sender == attacker, "not attacker");
        uint256 id = target.createRecord(
            patientId,
            incidentId,
            chiefComplaint,
            assessment,
            treatment
        );
        emit FakeRecordCreated(id);
        return id;
    }

    function tamperRecord(
        uint256 recordId,
        string calldata newChiefComplaint,
        string calldata newAssessment,
        string calldata newTreatment
    ) external {
        require(msg.sender == attacker, "not attacker");
        target.updateRecord(recordId, newChiefComplaint, newAssessment, newTreatment);
        emit RecordTampered(recordId);
    }

    function eraseRecord(uint256 recordId) external {
        require(msg.sender == attacker, "not attacker");
        target.deleteRecord(recordId);
        emit RecordErased(recordId);
    }
}


/* ========================================================= */
/* 3. SECURE ePCR – V2 DEFENSE                                */
/* ========================================================= */

contract ElectronicPatientCareReportingV2Defense {
    /*
     * Design:
     *   - Only EMT / ADMIN can create records.
     *   - Only the original EMT (or SUPERVISOR / MEDICAL_DIRECTOR / ADMIN)
     *     can update before lock.
     *   - Once locked, record is immutable.
     *   - PHI is kept off-chain as encrypted blob (URI); on-chain we store
     *     hashes & metadata only.
     *   - Hard delete is forbidden; only archive flag allowed.
     */

    enum Role {
        NONE,
        EMT,
        SUPERVISOR,
        MEDICAL_DIRECTOR,
        AUDITOR,
        ADMIN
    }

    enum RecordStatus {
        ACTIVE,
        ARCHIVED
    }

    struct EPCR {
        string patientPseudoId;   // pseudonym or hashed ID
        string incidentId;
        string dataURI;           // encrypted blob URI (IPFS/HTTPS)
        bytes32 contentHash;      // keccak256 of encrypted blob or canonical payload
        address createdBy;
        bool isLocked;
        RecordStatus status;
        bool exists;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct AuditLog {
        uint256 recordId;
        string action;            // "CREATED", "UPDATED", "LOCKED", "ARCHIVED"
        address actor;
        uint64 timestamp;
        bool exists;
    }

    address public systemAdmin;
    uint256 public recordCounter;
    uint256 public auditCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => EPCR) public records;
    mapping(uint256 => AuditLog) public audits;
    mapping(uint256 => uint256[]) public recordAudits; // recordId => audit IDs

    event RoleAssigned(address indexed account, Role role);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    event RecordCreated(
        uint256 indexed recordId,
        string patientPseudoId,
        string incidentId,
        address indexed createdBy
    );

    event RecordUpdated(uint256 indexed recordId, address indexed updatedBy);
    event RecordLocked(uint256 indexed recordId, address indexed lockedBy);
    event RecordArchived(uint256 indexed recordId, address indexed archivedBy);
    event AuditRecorded(uint256 indexed auditId, uint256 indexed recordId, string action);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyEMTOrHigher() {
        Role r = roles[msg.sender];
        require(
            r == Role.EMT ||
            r == Role.SUPERVISOR ||
            r == Role.MEDICAL_DIRECTOR ||
            r == Role.ADMIN,
            "not EMT/supervisor/director/admin"
        );
        _;
    }

    modifier onlySupervisorOrHigher() {
        Role r = roles[msg.sender];
        require(
            r == Role.SUPERVISOR ||
            r == Role.MEDICAL_DIRECTOR ||
            r == Role.ADMIN,
            "not supervisor/director/admin"
        );
        _;
    }

    modifier onlyAuditorOrHigher() {
        Role r = roles[msg.sender];
        require(
            r == Role.AUDITOR ||
            r == Role.SUPERVISOR ||
            r == Role.MEDICAL_DIRECTOR ||
            r == Role.ADMIN,
            "not auditor/supervisor/director/admin"
        );
        _;
    }

    constructor() {
        systemAdmin = msg.sender;
        roles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    /* ---------------- ROLE MANAGEMENT ---------------- */

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

    /* ---------------- RECORD CREATION ---------------- */

    function createRecord(
        string memory patientPseudoId,
        string memory incidentId,
        string memory dataURI,
        bytes32 contentHash
    ) external onlyEMTOrHigher returns (uint256) {
        require(bytes(patientPseudoId).length > 0, "patient id required");
        require(bytes(incidentId).length > 0, "incident id required");
        require(bytes(dataURI).length > 0, "dataURI required");
        require(contentHash != bytes32(0), "hash required");

        recordCounter++;
        uint256 id = recordCounter;

        records[id] = EPCR({
            patientPseudoId: patientPseudoId,
            incidentId: incidentId,
            dataURI: dataURI,
            contentHash: contentHash,
            createdBy: msg.sender,
            isLocked: false,
            status: RecordStatus.ACTIVE,
            exists: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        uint256 auditId = _addAudit(id, "CREATED");
        emit RecordCreated(id, patientPseudoId, incidentId, msg.sender);
        emit AuditRecorded(auditId, id, "CREATED");

        return id;
    }

    /* ---------------- RECORD UPDATE ---------------- */

    function updateRecord(
        uint256 recordId,
        string memory dataURI,
        bytes32 contentHash
    ) external onlyEMTOrHigher {
        EPCR storage r = records[recordId];
        require(r.exists, "no record");
        require(!r.isLocked, "locked");
        require(
            msg.sender == r.createdBy ||
            roles[msg.sender] == Role.SUPERVISOR ||
            roles[msg.sender] == Role.MEDICAL_DIRECTOR ||
            roles[msg.sender] == Role.ADMIN,
            "not owner or supervisor/director/admin"
        );

        require(bytes(dataURI).length > 0, "dataURI required");
        require(contentHash != bytes32(0), "hash required");

        r.dataURI = dataURI;
        r.contentHash = contentHash;
        r.updatedAt = uint64(block.timestamp);

        uint256 auditId = _addAudit(recordId, "UPDATED");
        emit RecordUpdated(recordId, msg.sender);
        emit AuditRecorded(auditId, recordId, "UPDATED");
    }

    /* ---------------- LOCK / ARCHIVE ---------------- */

    function lockRecord(uint256 recordId) external onlySupervisorOrHigher {
        EPCR storage r = records[recordId];
        require(r.exists, "no record");
        require(!r.isLocked, "already locked");

        r.isLocked = true;
        r.updatedAt = uint64(block.timestamp);

        uint256 auditId = _addAudit(recordId, "LOCKED");
        emit RecordLocked(recordId, msg.sender);
        emit AuditRecorded(auditId, recordId, "LOCKED");
    }

    function archiveRecord(uint256 recordId) external onlySupervisorOrHigher {
        EPCR storage r = records[recordId];
        require(r.exists, "no record");
        require(r.status == RecordStatus.ACTIVE, "already archived");

        r.status = RecordStatus.ARCHIVED;
        r.updatedAt = uint64(block.timestamp);

        uint256 auditId = _addAudit(recordId, "ARCHIVED");
        emit RecordArchived(recordId, msg.sender);
        emit AuditRecorded(auditId, recordId, "ARCHIVED");
    }

    /* ---------------- AUDIT ---------------- */

    function _addAudit(uint256 recordId, string memory action)
        internal
        returns (uint256)
    {
        auditCounter++;
        uint256 id = auditCounter;

        audits[id] = AuditLog({
            recordId: recordId,
            action: action,
            actor: msg.sender,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        recordAudits[recordId].push(id);
        return id;
    }

    function getAudit(uint256 auditId)
        external
        view
        onlyAuditorOrHigher
        returns (
            uint256 recordId,
            string memory action,
            address actor,
            uint64 timestamp,
            bool exists
        )
    {
        AuditLog storage a = audits[auditId];
        return (a.recordId, a.action, a.actor, a.timestamp, a.exists);
    }

    function getRecordAudits(uint256 recordId)
        external
        view
        onlyAuditorOrHigher
        returns (uint256[] memory)
    {
        return recordAudits[recordId];
    }

    /* ---------------- VIEWS ---------------- */

    function getRecord(uint256 recordId)
        external
        view
        returns (
            string memory patientPseudoId,
            string memory incidentId,
            string memory dataURI,
            bytes32 contentHash,
            address createdBy,
            bool isLocked,
            RecordStatus status,
            bool exists,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        EPCR storage r = records[recordId];
        return (
            r.patientPseudoId,
            r.incidentId,
            r.dataURI,
            r.contentHash,
            r.createdBy,
            r.isLocked,
            r.status,
            r.exists,
            r.createdAt,
            r.updatedAt
        );
    }

    function verifyContentHash(uint256 recordId, bytes32 expectedHash)
        external
        view
        returns (bool)
    {
        EPCR storage r = records[recordId];
        if (!r.exists) return false;
        return r.contentHash == expectedHash;
    }
}
