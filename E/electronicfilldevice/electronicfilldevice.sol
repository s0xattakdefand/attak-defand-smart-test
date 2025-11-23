// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
==============================================================
  ELECTRONIC FILL DEVICE (EFD) — SMART CONTRACT LAB
==============================================================

Purpose:
- An Electronic Fill Device holds cryptographic keys, mission data,
  radio configs, credentials, and loads them into secure systems.

This file includes:

1) ElectronicFillDeviceV1
      - Vulnerable implementation:
          * Anyone can load keys
          * Anyone can modify keys
          * Anyone can transfer keys to ANY device
          * Anyone can delete load logs

2) ElectronicFillDeviceAttacker
      - Attacker creates fake keys
      - Modifies mission data
      - Deletes audit history
      - Steals keys from devices

3) ElectronicFillDeviceV2Defense
      - Secure implementation:
          * Roles: LOADER, TECHNICIAN, AUDITOR, COMMAND, ADMIN
          * Full role-based key loading
          * Cryptographic hash of each key or mission data
          * Immutable load history (no delete)
          * Secure transfer protocol
          * Access-controlled fill operations
*/


/* ========================================================= */
/* 1. VULNERABLE ELECTRONIC FILL DEVICE (V1)                  */
/* ========================================================= */

contract ElectronicFillDeviceV1 {

    struct FillItem {
        string keyType;      // "AES256", "HMAC", "MissionData", "Config"
        string payload;      // raw key or config (plaintext ❌)
        address loadedBy;
        uint64 timestamp;
        bool exists;
    }

    struct LoadEvent {
        uint256 itemId;
        address fromDevice;
        address toDevice;
        string action;      // "LOADED", "TRANSFERRED"
        uint64 timestamp;
        bool exists;
    }

    uint256 public itemCounter;
    uint256 public eventCounter;

    mapping(uint256 => FillItem) public items;
    mapping(uint256 => LoadEvent) public events;
    mapping(address => uint256[]) public deviceItems; // device => item IDs

    event ItemLoaded(uint256 indexed itemId, address indexed device, string keyType);
    event ItemModified(uint256 indexed itemId);
    event ItemDeleted(uint256 indexed itemId);
    event EventDeleted(uint256 indexed eventId);

    /*
     * ⚠️ V1 Vulnerabilities:
     * - ANYONE can:
     *      * load keys
     *      * modify keys
     *      * transfer keys to any device
     *      * delete event history
     */

    function loadItem(address device, string memory keyType, string memory payload)
        external
        returns (uint256)
    {
        require(device != address(0), "dev zero");

        itemCounter++;
        uint256 id = itemCounter;

        items[id] = FillItem({
            keyType: keyType,
            payload: payload,
            loadedBy: msg.sender,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        deviceItems[device].push(id);

        _logEvent(id, address(0), device, "LOADED");

        emit ItemLoaded(id, device, keyType);
        return id;
    }

    // ⚠ Anyone can tamper a key or config
    function modifyItem(uint256 itemId, string memory newPayload) external {
        require(items[itemId].exists, "no item");

        items[itemId].payload = newPayload;
        items[itemId].timestamp = uint64(block.timestamp);

        emit ItemModified(itemId);
    }

    // ⚠ Anyone can delete keys
    function deleteItem(uint256 itemId) external {
        require(items[itemId].exists, "no item");
        delete items[itemId];
        emit ItemDeleted(itemId);
    }

    function transferItem(uint256 itemId, address fromDevice, address toDevice)
        external
        returns (uint256)
    {
        require(items[itemId].exists, "no item");
        require(toDevice != address(0), "to zero");

        deviceItems[toDevice].push(itemId);

        return _logEvent(itemId, fromDevice, toDevice, "TRANSFERRED");
    }

    // ⚠ Anyone can delete load history
    function deleteEvent(uint256 eventId) external {
        require(events[eventId].exists, "no event");
        delete events[eventId];
        emit EventDeleted(eventId);
    }

    function _logEvent(
        uint256 itemId,
        address fromDevice,
        address toDevice,
        string memory action
    ) internal returns (uint256) {
        eventCounter++;
        uint256 id = eventCounter;

        events[id] = LoadEvent({
            itemId: itemId,
            fromDevice: fromDevice,
            toDevice: toDevice,
            action: action,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        return id;
    }
}


/* ========================================================= */
/* 2. ATTACKER — KEY SPOOFING & AUDIT TAMPERING               */
/* ========================================================= */

contract ElectronicFillDeviceAttacker {
    ElectronicFillDeviceV1 public target;
    address public attacker;

    event FakeKeyInserted(uint256 indexed itemId);
    event KeyTampered(uint256 indexed itemId);
    event AuditErased(uint256 indexed eventId);

    constructor(address _target) {
        target = ElectronicFillDeviceV1(_target);
        attacker = msg.sender;
    }

    function injectFakeKey(address victimDevice, string calldata payload)
        external
        returns (uint256)
    {
        require(msg.sender == attacker, "not attacker");

        uint256 id = target.loadItem(victimDevice, "FAKE_KEY", payload);
        emit FakeKeyInserted(id);
        return id;
    }

    function tamperItem(uint256 itemId, string calldata newPayload) external {
        require(msg.sender == attacker, "not attacker");
        target.modifyItem(itemId, newPayload);
        emit KeyTampered(itemId);
    }

    function eraseAudit(uint256 eventId) external {
        require(msg.sender == attacker, "not attacker");
        target.deleteEvent(eventId);
        emit AuditErased(eventId);
    }
}


/* ========================================================= */
/* 3. SECURE ELECTRONIC FILL DEVICE — V2 DEFENSE              */
/* ========================================================= */

contract ElectronicFillDeviceV2Defense {

    enum Role {
        NONE,
        LOADER,        // loads keys
        TECHNICIAN,    // authorized to handle devices
        AUDITOR,       // can see logs
        COMMAND,       // high-level approval
        ADMIN          // full control
    }

    enum ItemStatus {
        ACTIVE,
        REVOKED
    }

    struct FillItem {
        string keyType;
        bytes32 hash;        // hash of key/config instead of plaintext
        address loadedBy;
        address device;
        uint64 timestamp;
        ItemStatus status;
        bool exists;
    }

    struct LoadEvent {
        uint256 itemId;
        address fromDevice;
        address toDevice;
        string action;
        uint64 timestamp;
        bool exists;
    }

    address public systemAdmin;
    uint256 public itemCounter;
    uint256 public eventCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => FillItem) public items;
    mapping(uint256 => LoadEvent) public events;
    mapping(address => uint256[]) public deviceItems;

    event RoleAssigned(address indexed user, Role role);

    event ItemLoaded(
        uint256 indexed itemId,
        address indexed device,
        string keyType,
        bytes32 hash
    );

    event ItemRevoked(uint256 indexed itemId);
    event ItemTransferred(uint256 indexed itemId, address from, address to);

    event AuditLogged(uint256 indexed eventId);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyLoaderOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.LOADER || r == Role.ADMIN, "not loader/admin");
        _;
    }

    modifier onlyTechOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.TECHNICIAN || r == Role.ADMIN, "not technician/admin");
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

    /* ---------------- ROLE MGMT ---------------- */

    function assignRole(address user, Role role) external onlyAdmin {
        require(user != address(0), "zero");
        require(role != Role.NONE, "invalid");
        roles[user] = role;
        emit RoleAssigned(user, role);
    }

    /* ---------------- KEY LOADING ---------------- */

    function loadItem(
        address device,
        string memory keyType,
        bytes32 keyHash
    ) external onlyLoaderOrAdmin returns (uint256) {

        require(device != address(0), "dev zero");
        require(keyHash != bytes32(0), "hash zero");

        itemCounter++;
        uint256 id = itemCounter;

        items[id] = FillItem({
            keyType: keyType,
            hash: keyHash,
            loadedBy: msg.sender,
            device: device,
            timestamp: uint64(block.timestamp),
            status: ItemStatus.ACTIVE,
            exists: true
        });

        deviceItems[device].push(id);

        uint256 eid = _logEvent(id, address(0), device, "LOADED");
        emit AuditLogged(eid);

        emit ItemLoaded(id, device, keyType, keyHash);

        return id;
    }

    /* ---------------- KEY TRANSFER ---------------- */

    function transferItem(
        uint256 itemId,
        address newDevice
    ) external onlyTechOrAdmin returns (uint256) {
        require(items[itemId].exists, "no item");
        require(newDevice != address(0), "zero");

        address oldDevice = items[itemId].device;
        items[itemId].device = newDevice;

        deviceItems[newDevice].push(itemId);

        uint256 eid = _logEvent(itemId, oldDevice, newDevice, "TRANSFERRED");
        emit AuditLogged(eid);

        emit ItemTransferred(itemId, oldDevice, newDevice);

        return eid;
    }

    /* ---------------- REVOKE KEYS ---------------- */

    function revokeItem(uint256 itemId) external onlyAdmin {
        require(items[itemId].exists, "no item");
        require(items[itemId].status == ItemStatus.ACTIVE, "already revoked");

        items[itemId].status = ItemStatus.REVOKED;
        emit ItemRevoked(itemId);
    }

    /* ---------------- AUDIT LOG ---------------- */

    function _logEvent(
        uint256 itemId,
        address fromDevice,
        address toDevice,
        string memory action
    ) internal returns (uint256) {
        eventCounter++;
        uint256 id = eventCounter;

        events[id] = LoadEvent({
            itemId: itemId,
            fromDevice: fromDevice,
            toDevice: toDevice,
            action: action,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        return id;
    }

    function getEvent(uint256 eventId)
        external
        view
        onlyAuditorOrAdmin
        returns (LoadEvent memory)
    {
        return events[eventId];
    }

    function getItem(uint256 itemId)
        external
        view
        returns (
            string memory keyType,
            bytes32 hash,
            address loadedBy,
            address device,
            ItemStatus status,
            bool exists
        )
    {
        FillItem storage i = items[itemId];
        return (
            i.keyType,
            i.hash,
            i.loadedBy,
            i.device,
            i.status,
            i.exists
        );
    }
}
