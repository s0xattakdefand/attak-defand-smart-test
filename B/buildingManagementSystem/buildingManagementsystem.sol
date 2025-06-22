// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BuildingManagementSystemAttackDefense - Attack and Defense Simulation for Building Management Systems in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Building Management System (No Subsystem Ownership Verification, No Emergency Path Protection)
contract InsecureBMS {
    mapping(string => address) public subsystems;

    event SubsystemUpdated(string indexed name, address indexed newAddress);
    event EmergencyShutdownTriggered(address indexed triggeredBy);

    function registerSubsystem(string calldata name, address subsystem) external {
        subsystems[name] = subsystem;
        emit SubsystemUpdated(name, subsystem);
    }

    function emergencyShutdown() external {
        // 🔥 Anyone can trigger shutdown without rate limit or role check!
        emit EmergencyShutdownTriggered(msg.sender);
    }
}

/// @notice Secure Building Management System with Subsystem Authorization, Emergency Hardening, and Access Roles
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureBMS is AccessControl {
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    mapping(string => address) public subsystems;
    bool public emergencyState;
    uint256 public lastEmergencyTrigger;
    uint256 public constant MIN_EMERGENCY_INTERVAL = 1 hours;

    event SubsystemRegistered(string indexed name, address indexed subsystem);
    event EmergencyTriggered(address indexed triggeredBy, uint256 timestamp);

    constructor(address initialManager, address initialEmergencyAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MANAGER_ROLE, initialManager);
        _grantRole(EMERGENCY_ROLE, initialEmergencyAdmin);
    }

    function registerSubsystem(string calldata name, address subsystem) external onlyRole(MANAGER_ROLE) {
        require(subsystem != address(0), "Invalid subsystem address");
        subsystems[name] = subsystem;
        emit SubsystemRegistered(name, subsystem);
    }

    function triggerEmergency() external onlyRole(EMERGENCY_ROLE) {
        require(!emergencyState, "Already in emergency");
        require(block.timestamp >= lastEmergencyTrigger + MIN_EMERGENCY_INTERVAL, "Emergency trigger too soon");

        emergencyState = true;
        lastEmergencyTrigger = block.timestamp;

        emit EmergencyTriggered(msg.sender, block.timestamp);
    }

    function resetEmergencyState() external onlyRole(DEFAULT_ADMIN_ROLE) {
        emergencyState = false;
    }

    function getSubsystem(string calldata name) external view returns (address) {
        return subsystems[name];
    }
}

/// @notice Intruder trying to hijack subsystem or trigger unauthorized emergency
contract BMSIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackSubsystem(string calldata name, address attacker) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("registerSubsystem(string,address)", name, attacker)
        );
    }

    function fakeEmergencyShutdown() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("emergencyShutdown()")
        );
    }
}
