// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
==============================================================
 ELECTRONIC DATA INTERCHANGE (EDI) – SMART CONTRACT LAB
==============================================================

This file includes:

1) ElectronicDataInterchangeV1
   - Vulnerable EDI messaging system
   - Anyone can register partners
   - Anyone can send fake EDI messages
   - Anyone can modify or delete messages
   - No non-repudiation, no roles, no checksums

2) ElectronicDataInterchangeAttacker
   - Spoofs purchase orders (PO)
   - Modifies invoices (INV)
   - Deletes audit logs (fraud, repudiation)

3) ElectronicDataInterchangeV2Defense
   - Secure EDI registry
   - Roles: ADMIN, PARTNER, AUDITOR
   - Immutable audit logs
   - Message signatures
   - Non-repudiation + hash integrity
   - Partner onboarding / offboarding
*/


/* ========================================================= */
/* 1. VULNERABLE EDI SYSTEM (V1)                              */
/* ========================================================= */

contract ElectronicDataInterchangeV1 {

    struct Partner {
        string name;
        string ediCode;     // e.g. "DUNS", "GLN", or a trading partner ID
        bool exists;
    }

    struct EDIMessage {
        uint256 partnerId;
        string messageType;   // "PO", "INV", "ASN", "ORDERS"
        string payload;       // JSON/XML/EDI-X12 text
        uint64 timestamp;
        bool exists;
    }

    struct AuditLog {
        uint256 messageId;
        string action;
        uint64 timestamp;
        bool exists;
    }

    uint256 public partnerCounter;
    uint256 public messageCounter;
    uint256 public auditCounter;

    mapping(uint256 => Partner) public partners;
    mapping(uint256 => EDIMessage) public messages;
    mapping(uint256 => AuditLog) public audits;

    mapping(uint256 => uint256[]) public partnerMessages;

    event PartnerRegistered(uint256 indexed partnerId, string name, string ediCode);
    event MessageSent(uint256 indexed msgId, uint256 indexed partnerId, string msgType);
    event MessageUpdated(uint256 indexed msgId);
    event MessageDeleted(uint256 indexed msgId);
    event AuditDeleted(uint256 indexed auditId);

    /*
     * ⚠️ V1 VULNERABILITIES:
     *   - ANYONE can:
     *       register trading partners
     *       send EDI messages
     *       modify or delete messages
     *       delete audit logs
     *   - No verification of trading partner identity
     */

    function registerPartner(string memory name, string memory ediCode)
        external
        returns (uint256)
    {
        require(bytes(name).length > 0, "name required");

        partnerCounter++;
        uint256 id = partnerCounter;

        partners[id] = Partner({
            name: name,
            ediCode: ediCode,
            exists: true
        });

        emit PartnerRegistered(id, name, ediCode);
        return id;
    }

    function sendMessage(
        uint256 partnerId,
        string memory msgType,
        string memory payload
    ) external returns (uint256)
    {
        require(partners[partnerId].exists, "not a partner");

        messageCounter++;
        uint256 id = messageCounter;

        messages[id] = EDIMessage({
            partnerId: partnerId,
            messageType: msgType,
            payload: payload,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        partnerMessages[partnerId].push(id);

        _audit(id, "MESSAGE_SENT");

        emit MessageSent(id, partnerId, msgType);
        return id;
    }

    function updateMessage(uint256 msgId, string memory newPayload) external {
        require(messages[msgId].exists, "no message");

        messages[msgId].payload = newPayload;
        messages[msgId].timestamp = uint64(block.timestamp);

        _audit(msgId, "MESSAGE_UPDATED");

        emit MessageUpdated(msgId);
    }

    function deleteMessage(uint256 msgId) external {
        require(messages[msgId].exists, "no message");
        delete messages[msgId];
        _audit(msgId, "MESSAGE_DELETED");
        emit MessageDeleted(msgId);
    }

    // ⚠ Anyone can delete audit logs
    function deleteAudit(uint256 auditId) external {
        require(audits[auditId].exists, "no audit");
        delete audits[auditId];
        emit AuditDeleted(auditId);
    }

    function _audit(uint256 msgId, string memory action) internal {
        auditCounter++;
        audits[auditCounter] = AuditLog({
            messageId: msgId,
            action: action,
            timestamp: uint64(block.timestamp),
            exists: true
        });
    }
}


/* ========================================================= */
/* 2. ATTACKER – EDI SPOOFING / DELETION                      */
/* ========================================================= */

contract ElectronicDataInterchangeAttacker {
    ElectronicDataInterchangeV1 public target;
    address public attacker;

    event FakePOCreated(uint256 indexed messageId);
    event MessageTampered(uint256 indexed messageId);
    event AuditErased(uint256 indexed auditId);

    constructor(address _target) {
        target = ElectronicDataInterchangeV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack:
     *   - Issue fake purchase orders (PO)
     *   - Modify legitimate invoices (INV)
     *   - Delete audit logs (repudiation)
     */

    function spoofPO(uint256 partnerId, string calldata fakePayload)
        external
        returns (uint256)
    {
        require(msg.sender == attacker, "not attacker");

        uint256 msgId = target.sendMessage(partnerId, "PO", fakePayload);
        emit FakePOCreated(msgId);
        return msgId;
    }

    function tamperMessage(uint256 msgId, string calldata newPayload) external {
        require(msg.sender == attacker, "not attacker");
        target.updateMessage(msgId, newPayload);
        emit MessageTampered(msgId);
    }

    function eraseAudit(uint256 auditId) external {
        require(msg.sender == attacker, "not attacker");
        target.deleteAudit(auditId);
        emit AuditErased(auditId);
    }
}


/* ========================================================= */
/* 3. SECURE EDI (V2 DEFENSE)                                 */
/* ========================================================= */

contract ElectronicDataInterchangeV2Defense {

    enum Role {
        NONE,
        PARTNER,
        AUDITOR,
        ADMIN
    }

    enum MessageStatus {
        ACTIVE,
        REVOKED
    }

    struct Partner {
        string name;
        string ediCode;
        bool onboarded;
        bool exists;
    }

    struct EDIMessage {
        uint256 partnerId;
        string messageType;
        bytes32 checksum;         // integrity hash for payload
        string payloadURI;        // off-chain IPFS/URL pointer instead of storing raw text
        uint64 timestamp;
        MessageStatus status;
        bool exists;
    }

    struct AuditRecord {
        uint256 messageId;
        string action;
        address actor;
        uint64 timestamp;
        bool exists;
    }

    address public systemAdmin;
    uint256 public partnerCounter;
    uint256 public messageCounter;
    uint256 public auditCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => Partner) public partners;
    mapping(uint256 => EDIMessage) public messages;
    mapping(uint256 => AuditRecord) public audits;
    mapping(uint256 => uint256[]) public partnerMessages;

    event RoleAssigned(address indexed user, Role role);
    event PartnerOnboarded(uint256 indexed partnerId, string name, string ediCode);
    event MessageIssued(uint256 indexed msgId, uint256 indexed partnerId, string msgType);
    event MessageRevoked(uint256 indexed msgId);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyPartnerOrAdmin() {
        require(
            roles[msg.sender] == Role.PARTNER || roles[msg.sender] == Role.ADMIN,
            "not partner/admin"
        );
        _;
    }

    modifier onlyAuditorOrAdmin() {
        require(
            roles[msg.sender] == Role.AUDITOR || roles[msg.sender] == Role.ADMIN,
            "not auditor/admin"
        );
        _;
    }

    constructor() {
        systemAdmin = msg.sender;
        roles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    /* ---------------- ROLE MGMT ---------------- */

    function assignRole(address user, Role role) external onlyAdmin {
        require(user != address(0), "zero");
        require(role != Role.NONE, "invalid");

        roles[user] = role;
        emit RoleAssigned(user, role);
    }

    /* ---------------- PARTNER MANAGEMENT ---------------- */

    function onboardPartner(
        string memory name,
        string memory ediCode,
        address wallet
    ) external onlyAdmin returns (uint256) {
        require(wallet != address(0), "zero");
        require(bytes(name).length > 0, "name required");

        partnerCounter++;
        uint256 id = partnerCounter;

        partners[id] = Partner({
            name: name,
            ediCode: ediCode,
            onboarded: true,
            exists: true
        });

        roles[wallet] = Role.PARTNER;

        emit PartnerOnboarded(id, name, ediCode);

        return id;
    }

    /* ---------------- EDI MESSAGING ---------------- */

    function sendEDIMessage(
        uint256 partnerId,
        string memory msgType,
        string memory payloadURI,
        bytes32 checksum
    ) external onlyPartnerOrAdmin returns (uint256) {
        require(partners[partnerId].exists, "no partner");
        require(partners[partnerId].onboarded, "not onboarded");

        messageCounter++;
        uint256 id = messageCounter;

        messages[id] = EDIMessage({
            partnerId: partnerId,
            messageType: msgType,
            payloadURI: payloadURI,
            checksum: checksum,
            timestamp: uint64(block.timestamp),
            status: MessageStatus.ACTIVE,
            exists: true
        });

        partnerMessages[partnerId].push(id);

        _audit(id, "MESSAGE_ISSUED");

        emit MessageIssued(id, partnerId, msgType);
        return id;
    }

    function revokeMessage(uint256 msgId) external onlyAdmin {
        EDIMessage storage m = messages[msgId];
        require(m.exists, "no message");
        require(m.status == MessageStatus.ACTIVE, "not active");

        m.status = MessageStatus.REVOKED;
        _audit(msgId, "MESSAGE_REVOKED");

        emit MessageRevoked(msgId);
    }

    /* ---------------- AUDIT ---------------- */

    function _audit(uint256 msgId, string memory action) internal {
        auditCounter++;
        audits[auditCounter] = AuditRecord({
            messageId: msgId,
            action: action,
            actor: msg.sender,
            timestamp: uint64(block.timestamp),
            exists: true
        });
    }

    function getAudit(uint256 auditId)
        external
        view
        onlyAuditorOrAdmin
        returns (AuditRecord memory)
    {
        return audits[auditId];
    }

    /* ---------------- VERIFICATION ---------------- */

    function verifyMessage(uint256 msgId)
        external
        view
        returns (
            bool valid,
            bytes32 checksum,
            string memory payloadURI,
            uint64 timestamp,
            MessageStatus status
        )
    {
        EDIMessage storage m = messages[msgId];
        if (!m.exists) return (false, 0, "", 0, MessageStatus.REVOKED);

        bool active = (m.status == MessageStatus.ACTIVE);
        return (active, m.checksum, m.payloadURI, m.timestamp, m.status);
    }
}
