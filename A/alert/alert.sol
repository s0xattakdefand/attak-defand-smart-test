// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract AlertManager is AccessControl {
    bytes32 public constant ALERT_TRIGGER_ROLE = keccak256("ALERT_TRIGGER_ROLE");

    uint256 public alertCooldown; 
    mapping(bytes32 => uint256) public lastAlertTimestamp;

    event AlertTriggered(address indexed triggeredBy, bytes32 indexed alertType, string details, uint256 timestamp);

    constructor(uint256 _alertCooldown) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        alertCooldown = _alertCooldown;  // Cooldown period in seconds
    }

    modifier cooldownPassed(bytes32 alertType) {
        require(
            block.timestamp >= lastAlertTimestamp[alertType] + alertCooldown,
            "Alert cooldown active"
        );
        _;
    }

    /// @notice Trigger an alert securely with details
    function triggerAlert(bytes32 alertType, string calldata details)
        external
        onlyRole(ALERT_TRIGGER_ROLE)
        cooldownPassed(alertType)
    {
        require(bytes(details).length > 0, "Alert details required");

        lastAlertTimestamp[alertType] = block.timestamp;

        emit AlertTriggered(msg.sender, alertType, details, block.timestamp);
    }

    /// @notice Update alert cooldown dynamically
    function setAlertCooldown(uint256 newCooldown) external onlyRole(DEFAULT_ADMIN_ROLE) {
        alertCooldown = newCooldown;
    }

    /// @notice Retrieve timestamp of last alert dynamically
    function getLastAlertTimestamp(bytes32 alertType) external view returns (uint256) {
        return lastAlertTimestamp[alertType];
    }
}
