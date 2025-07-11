// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DISTRIBUTED CONTROL SYSTEM DEMO
 * NIST SP 800-82r3 under “Distributed Control System”
 *
 * SECTION 1 — CentralizedControl (⚠️ vulnerable)
 *   • Single central owner controls all unit parameters.
 *   • No local autonomy for individual process units.
 *
 * SECTION 2 — DistributedControlSystem (✅ distributed intelligence)
 *   • Owner registers process units.
 *   • Owner grants per-unit controller roles.
 *   • Controllers set parameters for their own units.
 *   • Full audit via events.
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — CentralizedControl
/// -------------------------------------------------------------------------
contract CentralizedControl {
    // unitId → control parameter (e.g. setpoint)
    mapping(uint256 => uint256) public parameters;
    address public owner;

    event ParameterSet(uint256 indexed unitId, uint256 value, address indexed by);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), owner);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "CentralizedControl: only owner");
        _;
    }

    /// Transfer central ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "CentralizedControl: zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// Only owner may set any unit’s parameter
    function setParameter(uint256 unitId, uint256 value) external onlyOwner {
        parameters[unitId] = value;
        emit ParameterSet(unitId, value, msg.sender);
    }

    /// Anyone can read any unit’s parameter
    function getParameter(uint256 unitId) external view returns (uint256) {
        return parameters[unitId];
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — DistributedControlSystem
/// -------------------------------------------------------------------------
contract DistributedControlSystem {
    // unitId → control parameter
    mapping(uint256 => uint256) private _parameters;
    // unitId → controller address → allowed?
    mapping(uint256 => mapping(address => bool)) private _controllers;
    // list of registered units
    uint256[] public registeredUnits;
    // owner (the central authority that registers units and grants roles)
    address public owner;

    event UnitRegistered(uint256 indexed unitId);
    event ControllerGranted(uint256 indexed unitId, address indexed controller);
    event ControllerRevoked(uint256 indexed unitId, address indexed controller);
    event ParameterUpdated(uint256 indexed unitId, uint256 value, address indexed by);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), owner);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "DCS: only owner");
        _;
    }

    modifier onlyController(uint256 unitId) {
        require(_controllers[unitId][msg.sender], "DCS: not controller for unit");
        _;
    }

    /// Transfer system ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "DCS: zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// Owner registers a new process unit
    function registerUnit(uint256 unitId) external onlyOwner {
        require(!_unitExists(unitId), "DCS: unit already registered");
        registeredUnits.push(unitId);
        emit UnitRegistered(unitId);
    }

    /// Owner grants a controller permission for a specific unit
    function grantController(uint256 unitId, address controller) external onlyOwner {
        require(_unitExists(unitId), "DCS: unknown unit");
        _controllers[unitId][controller] = true;
        emit ControllerGranted(unitId, controller);
    }

    /// Owner revokes a controller’s permission for a unit
    function revokeController(uint256 unitId, address controller) external onlyOwner {
        require(_controllers[unitId][controller], "DCS: not a controller");
        _controllers[unitId][controller] = false;
        emit ControllerRevoked(unitId, controller);
    }

    /// Authorized controller sets the parameter for their unit
    function setParameter(uint256 unitId, uint256 value) external onlyController(unitId) {
        _parameters[unitId] = value;
        emit ParameterUpdated(unitId, value, msg.sender);
    }

    /// Anyone can read a unit’s parameter
    function getParameter(uint256 unitId) external view returns (uint256) {
        return _parameters[unitId];
    }

    /// Internal helper to check if a unit is registered
    function _unitExists(uint256 unitId) internal view returns (bool) {
        for (uint256 i = 0; i < registeredUnits.length; i++) {
            if (registeredUnits[i] == unitId) {
                return true;
            }
        }
        return false;
    }
}
