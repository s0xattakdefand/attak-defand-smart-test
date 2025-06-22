// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BuildElectricSystemAttackDefense - Attack and Defense Simulation for Build Electric Systems in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Build Electric System (No Quota Checks, No Emergency Role Separation)
contract InsecureElectricSystem {
    mapping(address => uint256) public energyBalance;
    bool public emergencyShutdown;

    event EnergyConsumed(address indexed consumer, uint256 amount);
    event EmergencyShutdownTriggered(address indexed triggeredBy);

    function allocateEnergy(address user, uint256 amount) external {
        energyBalance[user] += amount;
    }

    function consumeEnergy(uint256 amount) external {
        // 🔥 No balance check
        energyBalance[msg.sender] -= amount;
        emit EnergyConsumed(msg.sender, amount);
    }

    function triggerEmergencyShutdown() external {
        // 🔥 Anyone can shut down the system
        emergencyShutdown = true;
        emit EmergencyShutdownTriggered(msg.sender);
    }
}

/// @notice Secure Build Electric System with Quota Enforcement, Emergency Role Separation, and Validated Consumption
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureElectricSystem is AccessControl {
    bytes32 public constant GRID_MANAGER_ROLE = keccak256("GRID_MANAGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    mapping(address => uint256) public energyBalance;
    bool public emergencyShutdown;
    uint256 public lastEmergencyTrigger;
    uint256 public constant MIN_EMERGENCY_INTERVAL = 1 hours;

    event EnergyAllocated(address indexed user, uint256 amount);
    event EnergyConsumed(address indexed user, uint256 amount);
    event EmergencyShutdownTriggered(address indexed triggeredBy, uint256 timestamp);

    constructor(address manager, address emergencyAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GRID_MANAGER_ROLE, manager);
        _grantRole(EMERGENCY_ROLE, emergencyAdmin);
    }

    function allocateEnergy(address user, uint256 amount) external onlyRole(GRID_MANAGER_ROLE) {
        require(user != address(0), "Invalid user");
        energyBalance[user] += amount;
        emit EnergyAllocated(user, amount);
    }

    function consumeEnergy(uint256 amount) external {
        require(!emergencyShutdown, "Grid shutdown");
        require(energyBalance[msg.sender] >= amount, "Insufficient quota");

        energyBalance[msg.sender] -= amount;
        emit EnergyConsumed(msg.sender, amount);
    }

    function triggerEmergencyShutdown() external onlyRole(EMERGENCY_ROLE) {
        require(block.timestamp >= lastEmergencyTrigger + MIN_EMERGENCY_INTERVAL, "Too soon since last emergency");

        emergencyShutdown = true;
        lastEmergencyTrigger = block.timestamp;
        emit EmergencyShutdownTriggered(msg.sender, block.timestamp);
    }

    function resetGrid() external onlyRole(DEFAULT_ADMIN_ROLE) {
        emergencyShutdown = false;
    }
}

/// @notice Intruder trying to overconsume or force shutdown
contract ElectricIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function overdraftEnergy(uint256 fakeAmount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("consumeEnergy(uint256)", fakeAmount)
        );
    }

    function triggerFakeEmergency() external returns (bool success) {
        (success,
