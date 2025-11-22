// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTRONIC BIOMETRIC TRANSMISSION SPECIFICATION (EBTS) – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *   1) ElectronicBiometricTransmissionSpecificationV1
 *        – vulnerable biometric record + transmission registry
 *
 *   2) ElectronicBiometricTransmissionSpecificationAttacker
 *        – attacker that forges approvals and manipulates transmissions
 *
 *   3) ElectronicBiometricTransmissionSpecificationV2Defense
 *        – secure, role-based EBTS manager with immutable audit trail
 *
 *  Concept:
 *    - Agencies submit biometric records (fingerprint, face, iris, etc.).
 *    - Records get approved before they can be transmitted to destination systems.
 *    - Transmissions are logged (who, where, when, status).
 *
 *  V1 BUGS:
 *    - Anyone can approve any biometric record.
 *    - Anyone can change status of any transmission to "SENT".
 *    - Anyone can delete transmissions (erasing evidence).
 *
 *  V2 FIXES:
 *    - Roles: ADMIN, AGENCY, GATEWAY, AUDITOR
 *    - Only AGENCY/ADMIN can submit records.
 *    - Only ADMIN/AUDITOR can approve/revoke records.
 *    - Only GATEWAY/ADMIN can mark transmissions as sent/failed.
 *    - No delete; records/transmissions are immutable except state transitions.
 */


/* ============================================================= */
/* 1. VULNERABLE ELECTRONIC BIOMETRIC TRANSMISSION (EBTS) – V1   */
/* ============================================================= */

contract ElectronicBiometricTransmissionSpecificationV1 {
    struct BiometricRecord {
        string subjectId;      // internal subject / case identifier
        string modality;       // "FINGERPRINT", "FACE", "IRIS", etc.
        string dataHash;       // off-chain biometric template hash
        address submittedBy;
        bool approved;
        bool exists;
    }

    struct Transmission {
        uint256 recordId;
        string destinationSystem; // e.g. "AFIS_MAIN", "PARTNER_X"
        string status;            // "PENDING", "SENT", "FAILED", ...
        uint64 timestamp;
        address requestedBy;
        bool exists;
    }

    uint256 public recordCounter;
    uint256 public transmissionCounter;

    mapping(uint256 => BiometricRecord) public records;
    mapping(uint256 => Transmission) public transmissions;
    mapping(uint256 => uint256[]) public recordTransmissions; // recordId => transmissionIds

    event RecordSubmitted(
        uint256 indexed recordId,
        string subjectId,
        string modality,
        address submittedBy
    );

    event RecordApproved(
        uint256 indexed recordId,
        address approvedBy
    );

    event TransmissionRequested(
        uint256 indexed transmissionId,
        uint256 indexed recordId,
        string destinationSystem,
        address requestedBy
    );

    event TransmissionStatusChanged(
        uint256 indexed transmissionId,
        string newStatus,
        address changedBy
    );

    event TransmissionDeleted(uint256 indexed transmissionId);

    /*
     * ⚠️ V1 – NO ACCESS CONTROL
     *   - ANY address can:
     *       submitRecord, approveRecord, requestTransmission,
     *       updateTransmissionStatus, deleteTransmission
     */

    function submitRecord(
        string memory subjectId,
        string memory modality,
        string memory dataHash
    ) external returns (uint256) {
        require(bytes(subjectId).length > 0, "subjectId required");
        require(bytes(modality).length > 0, "modality required");
        require(bytes(dataHash).length > 0, "dataHash required");

        recordCounter++;
        uint256 id = recordCounter;

        records[id] = BiometricRecord({
            subjectId: subjectId,
            modality: modality,
            dataHash: dataHash,
            submittedBy: msg.sender,
            approved: false,
            exists: true
        });

        emit RecordSubmitted(id, subjectId, modality, msg.sender);
        return id;
    }

    // ⚠️ Anyone can approve any record
    function approveRecord(uint256 recordId) external {
        BiometricRecord storage r = records[recordId];
        require(r.exists, "no record");

        r.approved = true;
        emit RecordApproved(recordId, msg.sender);
    }

    function requestTransmission(
        uint256 recordId,
        string memory destinationSystem
    ) external returns (uint256) {
        BiometricRecord storage r = records[recordId];
        require(r.exists, "no record");
        require(bytes(destinationSystem).length > 0, "destination required");

        transmissionCounter++;
        uint256 tid = transmissionCounter;

        transmissions[tid] = Transmission({
            recordId: recordId,
            destinationSystem: destinationSystem,
            status: "PENDING",
            timestamp: uint64(block.timestamp),
            requestedBy: msg.sender,
            exists: true
        });

        recordTransmissions[recordId].push(tid);

        emit TransmissionRequested(tid, recordId, destinationSystem, msg.sender);
        return tid;
    }

    // ⚠️ Anyone can mark any transmission as "SENT" or whatever they like
    function updateTransmissionStatus(uint256 transmissionId, string memory newStatus) external {
        Transmission storage t = transmissions[transmissionId];
        require(t.exists, "no transmission");
        t.status = newStatus;
        emit TransmissionStatusChanged(transmissionId, newStatus, msg.sender);
    }

    // ⚠️ Anyone can delete transmissions (audit log tampering)
    function deleteTransmission(uint256 transmissionId) external {
        require(transmissions[transmissionId].exists, "no transmission");
        delete transmissions[transmissionId];
        emit TransmissionDeleted(transmissionId);
    }

    function getRecord(uint256 recordId)
        external
        view
        returns (
            string memory subjectId,
            string memory modality,
            string memory dataHash,
            address submittedBy,
            bool approved,
            bool exists
        )
    {
        BiometricRecord storage r = records[recordId];
        return (r.subjectId, r.modality, r.dataHash, r.submittedBy, r.approved, r.exists);
    }

    function getTransmission(uint256 transmissionId)
        external
        view
        returns (
            uint256 recordId,
            string memory destinationSystem,
            string memory status,
            uint64 timestamp,
            address requestedBy,
            bool exists
        )
    {
        Transmission storage t = transmissions[transmissionId];
        return (
            t.recordId,
            t.destinationSystem,
            t.status,
            t.timestamp,
            t.requestedBy,
            t.exists
        );
    }

    function getRecordTransmissions(uint256 recordId) external view returns (uint256[] memory) {
        return recordTransmissions[recordId];
    }
}


/* ============================================================= */
/*   2. ATTACKER – FORGE APPROVAL & MANIPULATE TRANSMISSIONS     */
/* ============================================================= */

contract ElectronicBiometricTransmissionSpecificationAttacker {
    ElectronicBiometricTransmissionSpecificationV1 public target;
    address public attacker;

    event FakeRecordApproved(uint256 indexed recordId);
    event FakeTransmissionStatus(uint256 indexed transmissionId, string status);
    event TransmissionErased(uint256 indexed transmissionId);

    constructor(address _target) {
        target = ElectronicBiometricTransmissionSpecificationV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack strategies:
     *
     *  1) Approve any biometric record (even fake ones).
     *  2) Mark transmissions as "SENT" without real gateway involvement.
     *  3) Delete transmission entries to erase audit trail.
     */

    function approveAnyRecord(uint256 recordId) external {
        require(msg.sender == attacker, "not attacker");
        target.approveRecord(recordId);
        emit FakeRecordApproved(recordId);
    }

    function forgeTransmissionStatus(uint256 transmissionId, string calldata status) external {
        require(msg.sender == attacker, "not attacker");
        target.updateTransmissionStatus(transmissionId, status);
        emit FakeTransmissionStatus(transmissionId, status);
    }

    function eraseTransmission(uint256 transmissionId) external {
        require(msg.sender == attacker, "not attacker");
        target.deleteTransmission(transmissionId);
        emit TransmissionErased(transmissionId);
    }
}


/* ============================================================= */
/* 3. SECURE ELECTRONIC BIOMETRIC TRANSMISSION – V2 DEFENSE      */
/* ============================================================= */

contract ElectronicBiometricTransmissionSpecificationV2Defense {
    enum Role {
        NONE,
        AGENCY,
        GATEWAY,
        AUDITOR,
        ADMIN
    }

    enum TransmissionStatus {
        PENDING,
        SENT,
        FAILED,
        CANCELLED
    }

    struct BiometricRecord {
        string subjectId;
        string modality;
        string dataHash;
        address submittedBy;
        address approvedBy;
        bool approved;
        bool revoked;
        bool exists;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct Transmission {
        uint256 recordId;
        string destinationSystem;
        TransmissionStatus status;
        address requestedBy;
        address gateway;
        uint64 createdAt;
        uint64 updatedAt;
        bool exists;
    }

    address public systemAdmin;
    uint256 public recordCounter;
    uint256 public transmissionCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => BiometricRecord) public records;
    mapping(uint256 => Transmission) public transmissions;
    mapping(uint256 => uint256[]) public recordTransmissions; // recordId => transmissionIds

    event RoleAssigned(address indexed account, Role role);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    event RecordSubmitted(
        uint256 indexed recordId,
        string subjectId,
        string modality,
        address submittedBy
    );

    event RecordApproved(
        uint256 indexed recordId,
        address approvedBy
    );

    event RecordRevoked(
        uint256 indexed recordId,
        address revokedBy
    );

    event TransmissionRequested(
        uint256 indexed transmissionId,
        uint256 indexed recordId,
        string destinationSystem,
        address requestedBy
    );

    event TransmissionStatusChanged(
        uint256 indexed transmissionId,
        TransmissionStatus newStatus,
        address changedBy
    );

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyAgencyOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.AGENCY || r == Role.ADMIN, "not agency/admin");
        _;
    }

    modifier onlyGatewayOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.GATEWAY || r == Role.ADMIN, "not gateway/admin");
        _;
    }

    modifier onlyAuditorOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.AUDITOR || r == Role.ADMIN, "not auditor/admin");
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

    // ---------------- RECORD MANAGEMENT ----------------

    function submitRecord(
        string memory subjectId,
        string memory modality,
        string memory dataHash
    ) external onlyAgencyOrAdmin returns (uint256) {
        require(bytes(subjectId).length > 0, "subjectId required");
        require(bytes(modality).length > 0, "modality required");
        require(bytes(dataHash).length > 0, "dataHash required");

        recordCounter++;
        uint256 id = recordCounter;

        records[id] = BiometricRecord({
            subjectId: subjectId,
            modality: modality,
            dataHash: dataHash,
            submittedBy: msg.sender,
            approvedBy: address(0),
            approved: false,
            revoked: false,
            exists: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit RecordSubmitted(id, subjectId, modality, msg.sender);
        return id;
    }

    /*
     * Only ADMIN or AUDITOR can approve.
     * Once revoked, cannot be approved again (requires new submission).
     */
    function approveRecord(uint256 recordId) external onlyAuditorOrAdmin {
        BiometricRecord storage r = records[recordId];
        require(r.exists, "no record");
        require(!r.revoked, "record revoked");
        require(!r.approved, "already approved");

        r.approved = true;
        r.approvedBy = msg.sender;
        r.updatedAt = uint64(block.timestamp);

        emit RecordApproved(recordId, msg.sender);
    }

    function revokeRecord(uint256 recordId) external onlyAuditorOrAdmin {
        BiometricRecord storage r = records[recordId];
        require(r.exists, "no record");
        require(!r.revoked, "already revoked");

        r.revoked = true;
        r.updatedAt = uint64(block.timestamp);

        emit RecordRevoked(recordId, msg.sender);
    }

    // ---------------- TRANSMISSION MANAGEMENT ----------------

    /*
     * Secure semantics:
     *   - Only AGENCY/ADMIN can request transmissions.
     *   - Record must be approved and not revoked.
     *   - Only GATEWAY/ADMIN can move status from PENDING -> SENT/FAILED.
     *   - No delete; all transmissions remain on-chain for audit.
     */

    function requestTransmission(
        uint256 recordId,
        string memory destinationSystem
    ) external onlyAgencyOrAdmin returns (uint256) {
        BiometricRecord storage r = records[recordId];
        require(r.exists, "no record");
        require(r.approved, "not approved");
        require(!r.revoked, "record revoked");
        require(bytes(destinationSystem).length > 0, "destination required");

        transmissionCounter++;
        uint256 tid = transmissionCounter;

        transmissions[tid] = Transmission({
            recordId: recordId,
            destinationSystem: destinationSystem,
            status: TransmissionStatus.PENDING,
            requestedBy: msg.sender,
            gateway: address(0),
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp),
            exists: true
        });

        recordTransmissions[recordId].push(tid);

        emit TransmissionRequested(tid, recordId, destinationSystem, msg.sender);
        return tid;
    }

    function markTransmissionSent(uint256 transmissionId) external onlyGatewayOrAdmin {
        Transmission storage t = transmissions[transmissionId];
        require(t.exists, "no transmission");
        require(t.status == TransmissionStatus.PENDING, "not pending");

        t.status = TransmissionStatus.SENT;
        t.gateway = msg.sender;
        t.updatedAt = uint64(block.timestamp);

        emit TransmissionStatusChanged(transmissionId, TransmissionStatus.SENT, msg.sender);
    }

    function markTransmissionFailed(uint256 transmissionId) external onlyGatewayOrAdmin {
        Transmission storage t = transmissions[transmissionId];
        require(t.exists, "no transmission");
        require(
            t.status == TransmissionStatus.PENDING ||
            t.status == TransmissionStatus.SENT,
            "invalid state"
        );

        t.status = TransmissionStatus.FAILED;
        t.gateway = msg.sender;
        t.updatedAt = uint64(block.timestamp);

        emit TransmissionStatusChanged(transmissionId, TransmissionStatus.FAILED, msg.sender);
    }

    function cancelTransmission(uint256 transmissionId) external onlyAdmin {
        Transmission storage t = transmissions[transmissionId];
        require(t.exists, "no transmission");
        require(
            t.status == TransmissionStatus.PENDING,
            "only pending can be cancelled"
        );

        t.status = TransmissionStatus.CANCELLED;
        t.updatedAt = uint64(block.timestamp);

        emit TransmissionStatusChanged(transmissionId, TransmissionStatus.CANCELLED, msg.sender);
    }

    // ---------------- VIEW HELPERS ----------------

    function getRecord(uint256 recordId)
        external
        view
        returns (
            string memory subjectId,
            string memory modality,
            string memory dataHash,
            address submittedBy,
            address approvedBy,
            bool approved,
            bool revoked,
            bool exists,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        BiometricRecord storage r = records[recordId];
        return (
            r.subjectId,
            r.modality,
            r.dataHash,
            r.submittedBy,
            r.approvedBy,
            r.approved,
            r.revoked,
            r.exists,
            r.createdAt,
            r.updatedAt
        );
    }

    function getTransmission(uint256 transmissionId)
        external
        view
        returns (
            uint256 recordId,
            string memory destinationSystem,
            TransmissionStatus status,
            address requestedBy,
            address gateway,
            bool exists,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        Transmission storage t = transmissions[transmissionId];
        return (
            t.recordId,
            t.destinationSystem,
            t.status,
            t.requestedBy,
            t.gateway,
            t.exists,
            t.createdAt,
            t.updatedAt
        );
    }

    function getRecordTransmissions(uint256 recordId) external view returns (uint256[] memory) {
        return recordTransmissions[recordId];
    }
}
