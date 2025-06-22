// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureAlarmSystem is AccessControl {
    bytes32 public constant ALARM_ADMIN_ROLE = keccak256("ALARM_ADMIN_ROLE");
    bytes32 public constant ALARM_TRIGGER_ROLE = keccak256("ALARM_TRIGGER_ROLE");

    uint256 public alarmCooldown; 
    uint256 public lastAlarmTimestamp;
    bool public alarmActive;

    event AlarmTriggered(address indexed triggeredBy, uint256 timestamp, string reason);
    event AlarmDeactivated(address indexed deactivatedBy, uint256 timestamp);

    constructor(uint256 _alarmCooldown) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        alarmCooldown = _alarmCooldown;  // cooldown in seconds
    }

    modifier alarmCooldownPassed() {
        require(block.timestamp >= lastAlarmTimestamp + alarmCooldown, "Alarm cooldown active");
        _;
    }

    /// @notice Trigger the alarm with a specific reason
    function triggerAlarm(string calldata reason) external onlyRole(ALARM_TRIGGER_ROLE) alarmCooldownPassed {
        alarmActive = true;
        lastAlarmTimestamp = block.timestamp;

        emit AlarmTriggered(msg.sender, block.timestamp, reason);
    }

    /// @notice Deactivate the alarm system manually by authorized admin
    function deactivateAlarm() external onlyRole(ALARM_ADMIN_ROLE) {
        require(alarmActive, "Alarm is not active");
        alarmActive = false;

        emit AlarmDeactivated(msg.sender, block.timestamp);
    }

    /// @notice Check alarm status
    function isAlarmActive() external view returns (bool) {
        return alarmActive;
    }

    /// @notice Adjust cooldown dynamically
    function setAlarmCooldown(uint256 newCooldown) external onlyRole(ALARM_ADMIN_ROLE) {
        alarmCooldown = newCooldown;
    }
}
