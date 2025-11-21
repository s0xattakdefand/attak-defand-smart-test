// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTRONIC ARTICLE SURVEILLANCE (EAS) – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *   1) ElectronicArticleSurveillanceV1
 *        – vulnerable item/tag registry and gate alarm logging
 *
 *   2) ElectronicArticleSurveillanceAttacker
 *        – attacker that disables tags and wipes alarms
 *
 *   3) ElectronicArticleSurveillanceV2Defense
 *        – secure, role-based EAS with immutable logs
 *
 *  Concept:
 *    - Each product/item in a store has an EAS tag.
 *    - Items pass through an exit gate; if tag is active, gate should alarm.
 *    - Staff can deactivate tags at checkout.
 *
 *    V1 BUGS:
 *      - Anyone can deactivate any item tag (bypass theft protection).
 *      - Anyone can mark an item as "untagged".
 *      - Anyone can delete gate events (erase evidence).
 *
 *    V2 FIXES:
 *      - Roles: ADMIN, CASHIER, SECURITY, GATE_DEVICE, USER
 *      - Only CASHIER/ADMIN can deactivate tags.
 *      - Only GATE_DEVICE/SECURITY can log exits.
 *      - Logs are immutable; no delete/overwrite.
 */


/* ============================================================= */
/*       1. VULNERABLE ELECTRONIC ARTICLE SURVEILLANCE (V1)      */
/* ============================================================= */

contract ElectronicArticleSurveillanceV1 {
    struct Item {
        string sku;         // product code
        bool hasTag;        // whether item is tagged at all
        bool tagActive;     // whether tag is active (should alarm)
        bool exists;
    }

    struct GateEvent {
        uint256 itemId;
        address actor;
        bool alarm;         // true if gate alarmed
        uint64 timestamp;
        bool exists;
    }

    uint256 public itemCounter;
    uint256 public eventCounter;

    mapping(uint256 => Item) public items;
    mapping(uint256 => GateEvent) public events;
    mapping(uint256 => uint256[]) public itemEvents; // itemId => eventIds

    event ItemRegistered(uint256 indexed itemId, string sku, bool hasTag, bool tagActive);
    event ItemUpdated(uint256 indexed itemId, bool hasTag, bool tagActive);
    event GateEventRecorded(uint256 indexed eventId, uint256 indexed itemId, bool alarm, address actor);
    event GateEventDeleted(uint256 indexed eventId);

    /*
     * ⚠️ V1 – NO ACCESS CONTROL
     *   - ANY address can:
     *       registerItem, updateTagStatus, simulateExit, deleteGateEvent
     *   - Thief can:
     *       set tagActive = false, then exit without alarm, then delete logs.
     */

    function registerItem(
        string memory sku,
        bool hasTag,
        bool tagActive
    ) external returns (uint256) {
        require(bytes(sku).length > 0, "sku required");

        itemCounter++;
        uint256 id = itemCounter;

        items[id] = Item({
            sku: sku,
            hasTag: hasTag,
            tagActive: tagActive,
            exists: true
        });

        emit ItemRegistered(id, sku, hasTag, tagActive);
        return id;
    }

    // ⚠️ Anyone can change tag state (including deactivating tags)
    function updateTagStatus(
        uint256 itemId,
        bool newHasTag,
        bool newTagActive
    ) external {
        Item storage it = items[itemId];
        require(it.exists, "no item");

        it.hasTag = newHasTag;
        it.tagActive = newTagActive;

        emit ItemUpdated(itemId, newHasTag, newTagActive);
    }

    // Simulate passing through gate
    function simulateExit(uint256 itemId) external returns (uint256) {
        Item storage it = items[itemId];
        require(it.exists, "no item");

        bool alarm = it.hasTag && it.tagActive;

        eventCounter++;
        uint256 eid = eventCounter;

        events[eid] = GateEvent({
            itemId: itemId,
            actor: msg.sender,
            alarm: alarm,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        itemEvents[itemId].push(eid);

        emit GateEventRecorded(eid, itemId, alarm, msg.sender);
        return eid;
    }

    // ⚠️ Anyone can delete logs
    function deleteGateEvent(uint256 eventId) external {
        require(events[eventId].exists, "no event");
        delete events[eventId];
        emit GateEventDeleted(eventId);
    }

    function getItem(uint256 itemId)
        external
        view
        returns (string memory sku, bool hasTag, bool tagActive, bool exists)
    {
        Item storage it = items[itemId];
        return (it.sku, it.hasTag, it.tagActive, it.exists);
    }

    function getGateEvent(uint256 eventId)
        external
        view
        returns (uint256 itemId, address actor, bool alarm, uint64 timestamp, bool exists)
    {
        GateEvent storage e = events[eventId];
        return (e.itemId, e.actor, e.alarm, e.timestamp, e.exists);
    }

    function getItemEvents(uint256 itemId) external view returns (uint256[] memory) {
        return itemEvents[itemId];
    }
}


/* ============================================================= */
/*   2. ATTACKER – DISABLE TAGS & WIPE ELECTRONIC SURVEILLANCE   */
/* ============================================================= */

contract ElectronicArticleSurveillanceAttacker {
    ElectronicArticleSurveillanceV1 public target;
    address public attacker;

    event TagDisabled(uint256 indexed itemId);
    event LogsWiped(uint256[] eventIds);

    constructor(address _target) {
        target = ElectronicArticleSurveillanceV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack pattern:
     *  - For an item the attacker wants to steal:
     *      1) Call updateTagStatus(itemId, true, false) to disable tag.
     *      2) Call simulateExit(itemId) – alarm is now false.
     *      3) Optionally deleteGateEvent() to wipe record of the attempt.
     */

    function disableTag(uint256 itemId) external {
        require(msg.sender == attacker, "not attacker");
        // hasTag=true but tagActive=false (looks like tag present but is effectively off)
        target.updateTagStatus(itemId, true, false);
        emit TagDisabled(itemId);
    }

    function exitWithDisabledTag(uint256 itemId) external {
        require(msg.sender == attacker, "not attacker");
        target.simulateExit(itemId);
        // If system trusted V1, no alarm is raised
    }

    function wipeEvents(uint256[] calldata eventIds) external {
        require(msg.sender == attacker, "not attacker");
        for (uint256 i = 0; i < eventIds.length; i++) {
            target.deleteGateEvent(eventIds[i]);
        }
        emit LogsWiped(eventIds);
    }
}


/* ============================================================= */
/* 3. SECURE ELECTRONIC ARTICLE SURVEILLANCE (V2 DEFENSE)        */
/* ============================================================= */

contract ElectronicArticleSurveillanceV2Defense {
    enum Role {
        NONE,
        USER,
        CASHIER,
        SECURITY,
        GATE_DEVICE,
        ADMIN
    }

    struct Item {
        string sku;
        bool hasTag;
        bool tagActive;
        bool exists;
        uint64 createdAt;
        uint64 updatedAt;
    }

    struct GateEvent {
        uint256 itemId;
        address actor;
        bool alarm;
        uint64 timestamp;
        bool exists;
    }

    address public systemAdmin;
    uint256 public itemCounter;
    uint256 public eventCounter;

    mapping(address => Role) public roles;
    mapping(uint256 => Item) public items;
    mapping(uint256 => GateEvent) public events;
    mapping(uint256 => uint256[]) public itemEvents; // itemId => eventIds

    event RoleAssigned(address indexed account, Role role);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    event ItemRegistered(uint256 indexed itemId, string sku, bool hasTag, bool tagActive);
    event ItemTagUpdated(uint256 indexed itemId, bool hasTag, bool tagActive, address indexed by);
    event GateEventRecorded(uint256 indexed eventId, uint256 indexed itemId, bool alarm, address actor);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "not admin");
        _;
    }

    modifier onlyCashierOrAdmin() {
        Role r = roles[msg.sender];
        require(r == Role.CASHIER || r == Role.ADMIN, "not cashier/admin");
        _;
    }

    modifier onlyGateOrSecurityOrAdmin() {
        Role r = roles[msg.sender];
        require(
            r == Role.GATE_DEVICE || r == Role.SECURITY || r == Role.ADMIN,
            "not gate/security/admin"
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

    // ---------------- ITEM / TAG MANAGEMENT ----------------

    function registerItem(
        string memory sku,
        bool hasTag,
        bool tagActive
    ) external onlyAdmin returns (uint256) {
        require(bytes(sku).length > 0, "sku required");

        itemCounter++;
        uint256 id = itemCounter;

        items[id] = Item({
            sku: sku,
            hasTag: hasTag,
            tagActive: tagActive,
            exists: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit ItemRegistered(id, sku, hasTag, tagActive);
        return id;
    }

    /*
     * Tag modification is restricted:
     *   - CASHIER / ADMIN can deactivate tags (checkout).
     *   - SECURITY / ADMIN can re-activate tags if needed.
     */

    function deactivateTagAtCheckout(uint256 itemId) external onlyCashierOrAdmin {
        Item storage it = items[itemId];
        require(it.exists, "no item");
        require(it.hasTag, "no tag");
        require(it.tagActive, "already inactive");

        it.tagActive = false;
        it.updatedAt = uint64(block.timestamp);

        emit ItemTagUpdated(itemId, it.hasTag, it.tagActive, msg.sender);
    }

    function reactivateTag(uint256 itemId) external {
        Role r = roles[msg.sender];
        require(r == Role.SECURITY || r == Role.ADMIN, "not security/admin");

        Item storage it = items[itemId];
        require(it.exists, "no item");
        require(it.hasTag, "no tag");

        it.tagActive = true;
        it.updatedAt = uint64(block.timestamp);

        emit ItemTagUpdated(itemId, it.hasTag, it.tagActive, msg.sender);
    }

    // ---------------- GATE / ALARM LOGGING ----------------

    /*
     *  In V2:
     *    - Only GATE_DEVICE, SECURITY, or ADMIN can log an exit attempt.
     *    - Logs are immutable (no delete function).
     *    - Alarm is computed from item.hasTag && item.tagActive at the time of exit.
     */

    function logExit(uint256 itemId) external onlyGateOrSecurityOrAdmin returns (uint256) {
        Item storage it = items[itemId];
        require(it.exists, "no item");

        bool alarm = it.hasTag && it.tagActive;

        eventCounter++;
        uint256 eid = eventCounter;

        events[eid] = GateEvent({
            itemId: itemId,
            actor: msg.sender,
            alarm: alarm,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        itemEvents[itemId].push(eid);

        emit GateEventRecorded(eid, itemId, alarm, msg.sender);
        return eid;
    }

    // ---------------- VIEW HELPERS ----------------

    function getItem(uint256 itemId)
        external
        view
        returns (
            string memory sku,
            bool hasTag,
            bool tagActive,
            bool exists,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        Item storage it = items[itemId];
        return (it.sku, it.hasTag, it.tagActive, it.exists, it.createdAt, it.updatedAt);
    }

    function getGateEvent(uint256 eventId)
        external
        view
        returns (
            uint256 itemId,
            address actor,
            bool alarm,
            uint64 timestamp,
            bool exists
        )
    {
        GateEvent storage e = events[eventId];
        return (e.itemId, e.actor, e.alarm, e.timestamp, e.exists);
    }

    function getItemEvents(uint256 itemId) external view returns (uint256[] memory) {
        return itemEvents[itemId];
    }
}
