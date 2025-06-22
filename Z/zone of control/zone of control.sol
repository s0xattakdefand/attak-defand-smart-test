// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ZoneOfControlManager — Enforces strict contract/module/user boundaries within a security zone
contract ZoneOfControlManager {
    address public immutable zoneAnchor;
    address public controller;
    bool public locked;

    mapping(address => bool) public zoneMembers;     // e.g., trusted addresses
    mapping(address => bool) public logicModules;    // e.g., authorized internal logic
    mapping(bytes32 => bool) public authorizedRoles; // e.g., keccak256("ZONE_ADMIN")

    event MemberAdded(address indexed member);
    event MemberRemoved(address indexed member);
    event ModuleAdded(address indexed module);
    event ModuleRevoked(address indexed module);
    event RoleGranted(bytes32 indexed role);
    event ZoneLocked(address by);

    modifier onlyController() {
        require(msg.sender == controller, "Not controller");
        _;
    }

    modifier zoneOpen() {
        require(!locked, "Zone is locked");
        _;
    }

    constructor() {
        controller = msg.sender;
        zoneAnchor = keccak256("ZoneOfControl.Main.v1");
    }

    /// 🔐 Add/Remove addresses in the zone of control
    function addMember(address member) external onlyController zoneOpen {
        zoneMembers[member] = true;
        emit MemberAdded(member);
    }

    function removeMember(address member) external onlyController {
        zoneMembers[member] = false;
        emit MemberRemoved(member);
    }

    /// 🔐 Add/Remove authorized modules
    function addModule(address module) external onlyController zoneOpen {
        logicModules[module] = true;
        emit ModuleAdded(module);
    }

    function revokeModule(address module) external onlyController {
        logicModules[module] = false;
        emit ModuleRevoked(module);
    }

    /// 🔐 Grant operational role
    function grantRole(bytes32 role) external onlyController zoneOpen {
        authorizedRoles[role] = true;
        emit RoleGranted(role);
    }

    /// 🔐 Lock the zone (no further entry/editing)
    function lockZone() external onlyController {
        locked = true;
        emit ZoneLocked(msg.sender);
    }

    /// Read-only check functions
    function isZoneMember(address addr) external view returns (bool) {
        return zoneMembers[addr];
    }

    function isAuthorizedModule(address module) external view returns (bool) {
        return logicModules[module];
    }

    function hasZoneRole(bytes32 role) external view returns (bool) {
        return authorizedRoles[role];
    }
}
