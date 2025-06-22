// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BuildingAutomationSystemAttackDefense - Attack and Defense Simulation for Building Automation Systems in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Building Automation (No Access Control, No Rate Limit, No Change Logs)
contract InsecureBAS {
    mapping(string => bool) public systemsStatus;

    event SystemTriggered(string systemName, bool active);

    function triggerSystem(string calldata systemName, bool active) external {
        // 🔥 Anyone can trigger any system anytime
        systemsStatus[systemName] = active;
        emit SystemTriggered(systemName, active);
    }
}

/// @notice Secure Building Automation with Access Control, Rate Limiting, and Immutable Logging
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureBAS is AccessControl {
    bytes32 public constant AUTOMATION_ROLE = keccak256("AUTOMATION_ROLE");

    mapping(string => bool) public systemsStatus;
    mapping(string => uint256) public lastTriggered;
    uint256 public constant MIN_TRIGGER_INTERVAL = 5 minutes;

    event SystemTriggered(string systemName, bool active, uint256 timestamp);

    constructor(address initialAutomationAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(AUTOMATION_ROLE, initialAutomationAdmin);
    }

    function triggerSystem(string calldata systemName, bool active) external onlyRole(AUTOMATION_ROLE) {
        require(block.timestamp >= lastTriggered[systemName] + MIN_TRIGGER_INTERVAL, "Trigger rate too high");

        systemsStatus[systemName] = active;
        lastTriggered[systemName] = block.timestamp;

        emit SystemTriggered(systemName, active, block.timestamp);
    }

    function systemStatus(string calldata systemName) external view returns (bool) {
        return systemsStatus[systemName];
    }
}

/// @notice Intruder trying to abuse automation
contract BASIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function spamTrigger(string calldata systemName, bool active) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("triggerSystem(string,bool)", systemName, active)
        );
    }
}
