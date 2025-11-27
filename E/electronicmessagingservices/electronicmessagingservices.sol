// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
====================================================================
 ELECTRONIC MESSAGING SERVICES — SMART CONTRACT LAB
====================================================================

This includes:

1️⃣ ElectronicMessagingServicesV1 (Insecure)
    - Anyone can send/modify/delete messages
    - No identity verification
    - No protection against spoofing
    - No message integrity checks
    - No audit protections

2️⃣ ElectronicMessagingServicesAttacker
    - Spoof sender identity
    - Modify messages
    - Delete messages to erase evidence

3️⃣ ElectronicMessagingServicesV2Defense
    - Secure role-based messaging system
    - Sender always = msg.sender (no spoofing)
    - Immutable content (hash-protected)
    - Soft-delete instead of full deletion
    - Full audit logs (immutable)
    - Registered users only
    - Optional public-key metadata
*/


/* ================================================================ */
/* 1. VULNERABLE ELECTRONIC MESSAGING SYSTEM (V1)                    */
/* ================================================================ */

contract ElectronicMessagingServicesV1 {

    struct Message {
        address from;
        address to;
        string subject;
        string body;
        uint64 timestamp;
        bool exists;
    }

    uint256 public msgCounter;

    mapping(uint256 => Message) public messages;
    mapping(address => uint256[]) public inbox;
    mapping(address => uint256[]) public outbox;

    event MessageSent(uint256 msgId, address from, address to);
    event MessageUpdated(uint256 msgId);
    event MessageDeleted(uint256 msgId);

    /*
     * ⚠️ V1 SECURITY PROBLEMS:
     * - Sender address is passed in, so anyone can spoof
     * - Messages can be edited by ANYONE
     * - Messages can be deleted by ANYONE
     */

    function sendMessage(
        address from,
        address to,
        string memory subject,
        string memory body
    )
        external
        returns (uint256)
    {
        require(to != address(0), "to zero addr");

        msgCounter++;
        uint256 id = msgCounter;

        messages[id] = Message({
            from: from,        // ⚠️ SPOOFABLE
            to: to,
            subject: subject,
            body: body,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        inbox[to].push(id);
        outbox[from].push(id);

        emit MessageSent(id, from, to);
        return id;
    }

    // ⚠️ ANYONE can modify message content
    function modifyMessage(uint256 msgId, string memory newSubj, string memory newBody)
        external
    {
        require(messages[msgId].exists, "no msg");
        Message storage m = messages[msgId];
        m.subject = newSubj;
        m.body = newBody;
        m.timestamp = uint64(block.timestamp);
        emit MessageUpdated(msgId);
    }

    // ⚠️ ANYONE can delete the message
    function deleteMessage(uint256 msgId) external {
        require(messages[msgId].exists, "no msg");
        delete messages[msgId];
        emit MessageDeleted(msgId);
    }

    function getInbox(address user) external view returns (uint256[] memory) {
        return inbox[user];
    }

    function getOutbox(address user) external view returns (uint256[] memory) {
        return outbox[user];
    }

    function getMessage(uint256 msgId)
        external
        view
        returns (
            address from,
            address to,
            string memory subject,
            string memory body,
            uint64 timestamp,
            bool exists
        )
    {
        Message storage m = messages[msgId];
        return (m.from, m.to, m.subject, m.body, m.timestamp, m.exists);
    }
}


/* ================================================================ */
/* 2. ATTACKER — SPOOFING, TAMPERING, DELETING                      */
/* ================================================================ */

contract ElectronicMessagingServicesAttacker {
    ElectronicMessagingServicesV1 public target;
    address public attacker;

    event SpoofedMessage(uint256 msgId);
    event MessageTampered(uint256 msgId);
    event MessageErased(uint256 msgId);

    constructor(address _target) {
        target = ElectronicMessagingServicesV1(_target);
        attacker = msg.sender;
    }

    function spoofSender(
        address fakeSender,
        address recipient,
        string calldata subject,
        string calldata body
    ) external returns (uint256) {
        require(msg.sender == attacker, "not attacker");
        uint256 id = target.sendMessage(fakeSender, recipient, subject, body);
        emit SpoofedMessage(id);
        return id;
    }

    function tamperMessage(uint256 msgId, string calldata newSubj, string calldata newBody)
        external
    {
        require(msg.sender == attacker, "not attacker");
        target.modifyMessage(msgId, newSubj, newBody);
        emit MessageTampered(msgId);
    }

    function eraseMessage(uint256 msgId) external {
        require(msg.sender == attacker, "not attacker");
        target.deleteMessage(msgId);
        emit MessageErased(msgId);
    }
}


/* ================================================================ */
/* 3. SECURE ELECTRONIC MESSAGING SYSTEM (V2 DEFENSE)                */
/* ================================================================ */

contract ElectronicMessagingServicesV2Defense {

    enum Role {
        NONE,
        USER,
        AUDITOR,
        ADMIN
    }

    struct User {
        string displayName;
        string publicKeyInfo;  // OPTIONAL: PGP key, signature key, etc.
        bool active;
        bool exists;
    }

    struct Message {
        address from;
        address to;
        string subject;
        string body;
        bytes32 hash;         // integrity hash
        uint64 timestamp;
        bool deletedBySender;
        bool deletedByRecipient;
        bool exists;
    }

    struct Audit {
        uint256 msgId;
        string action; // SENT, DELETED_BY_SENDER, DELETED_BY_RECIPIENT
        address actor;
        uint64 timestamp;
        bool exists;
    }

    address public admin;

    uint256 public msgCounter;
    uint256 public auditCounter;

    mapping(address => Role) public roles;
    mapping(address => User) public users;
    mapping(uint256 => Message) public messages;
    mapping(address => uint256[]) public inbox;
    mapping(address => uint256[]) public outbox;
    mapping(uint256 => Audit) public audits;

    event UserRegistered(address user, string name);
    event RoleAssigned(address user, Role role);
    event MessageSent(uint256 msgId, address indexed from, address indexed to);
    event SoftDelete(uint256 msgId, address by);
    event AuditRecorded(uint256 auditId, uint256 msgId, string action);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyUserOrAdmin() {
        require(
            roles[msg.sender] == Role.USER || roles[msg.sender] == Role.ADMIN,
            "not user/admin"
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
        admin = msg.sender;
        roles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    /* ----------------- USER MANAGEMENT ----------------- */

    function registerUser(string calldata name, string calldata keyInfo) external {
        User storage u = users[msg.sender];
        u.displayName = name;
        u.publicKeyInfo = keyInfo;
        u.active = true;
        u.exists = true;

        roles[msg.sender] = Role.USER;

        emit UserRegistered(msg.sender, name);
        emit RoleAssigned(msg.sender, Role.USER);
    }

    function deactivateUser(address user) external onlyAdmin {
        require(users[user].exists, "no user");
        users[user].active = false;
    }

    /* ----------------- ROLE MGMT ----------------- */

    function assignRole(address user, Role r) external onlyAdmin {
        require(user != address(0), "zero");
        require(r != Role.NONE, "invalid");
        roles[user] = r;
        emit RoleAssigned(user, r);
    }

    /* ----------------- SENDING MESSAGES ----------------- */

    function sendMessage(
        address to,
        string calldata subject,
        string calldata body
    ) external onlyUserOrAdmin returns (uint256) {

        require(users[msg.sender].active, "sender inactive");
        require(users[to].active, "recipient inactive");

        msgCounter++;
        uint256 id = msgCounter;

        bytes32 hash = keccak256(abi.encodePacked(subject, body));

        messages[id] = Message({
            from: msg.sender,
            to: to,
            subject: subject,
            body: body,
            hash: hash,
            timestamp: uint64(block.timestamp),
            deletedBySender: false,
            deletedByRecipient: false,
            exists: true
        });

        inbox[to].push(id);
        outbox[msg.sender].push(id);

        uint256 auditId = _audit(id, "SENT");

        emit MessageSent(id, msg.sender, to);
        emit AuditRecorded(auditId, id, "SENT");

        return id;
    }

    /* ----------------- SOFT DELETE ----------------- */

    function deleteMessageForMe(uint256 msgId) external {
        Message storage m = messages[msgId];
        require(m.exists, "no msg");
        require(msg.sender == m.from || msg.sender == m.to, "not owner");

        if (msg.sender == m.from) {
            m.deletedBySender = true;
            uint256 a1 = _audit(msgId, "DELETED_BY_SENDER");
            emit AuditRecorded(a1, msgId, "DELETED_BY_SENDER");
        }

        if (msg.sender == m.to) {
            m.deletedByRecipient = true;
            uint256 a2 = _audit(msgId, "DELETED_BY_RECIPIENT");
            emit AuditRecorded(a2, msgId, "DELETED_BY_RECIPIENT");
        }

        emit SoftDelete(msgId, msg.sender);
    }

    /* ----------------- AUDIT ----------------- */

    function _audit(uint256 msgId, string memory action) internal returns (uint256) {
        auditCounter++;
        uint256 id = auditCounter;

        audits[id] = Audit({
            msgId: msgId,
            action: action,
            actor: msg.sender,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        return id;
    }

    function getAudit(uint256 id)
        external
        view
        onlyAuditorOrAdmin
        returns (Audit memory)
    {
        return audits[id];
    }

    /* ----------------- VERIFY MESSAGE INTEGRITY ----------------- */

    function verifyContent(
        uint256 msgId,
        string calldata subject,
        string calldata body
    ) external view returns (bool) {
        Message storage m = messages[msgId];
        if (!m.exists) return false;
        return m.hash == keccak256(abi.encodePacked(subject, body));
    }

    /* ----------------- VIEWS ----------------- */

    function getInbox(address user) external view returns (uint256[] memory) {
        return inbox[user];
    }

    function getOutbox(address user) external view returns (uint256[] memory) {
        return outbox[user];
    }

    function getMessage(uint256 msgId)
        external
        view
        returns (
            address from,
            address to,
            string memory subject,
            string memory body,
            uint64 timestamp,
            bool senderDeleted,
            bool recipientDeleted,
            bool exists
        )
    {
        Message storage m = messages[msgId];
        return (
            m.from,
            m.to,
            m.subject,
            m.body,
            m.timestamp,
            m.deletedBySender,
            m.deletedByRecipient,
            m.exists
        );
    }
}
