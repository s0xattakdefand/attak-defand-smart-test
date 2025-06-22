// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Web3 Actuator System — Controls who can trigger what

contract ActuatorSystem {
    address public admin;
    bool public systemActive;

    enum Role { NONE, ACTUATOR, ADMIN }
    mapping(address => Role) public roles;

    event ActionTriggered(address indexed actuator, string action);
    event ActuatorAssigned(address indexed user);
    event ActuatorRevoked(address indexed user);
    event SystemStatusChanged(bool status);
    event AttackDetected(address indexed by, string reason);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "Not admin");
        _;
    }

    modifier onlyActuator() {
        if (roles[msg.sender] != Role.ACTUATOR) {
            emit AttackDetected(msg.sender, "Unauthorized actuator");
            revert("Actuator access denied");
        }
        _;
    }

    modifier systemLive() {
        require(systemActive, "System paused");
        _;
    }

    constructor() {
        admin = msg.sender;
        roles[admin] = Role.ADMIN;
        systemActive = true;
    }

    // Admin controls actuator assignments
    function assignActuator(address user) external onlyAdmin {
        roles[user] = Role.ACTUATOR;
        emit ActuatorAssigned(user);
    }

    function revokeActuator(address user) external onlyAdmin {
        roles[user] = Role.NONE;
        emit ActuatorRevoked(user);
    }

    function toggleSystem(bool live) external onlyAdmin {
        systemActive = live;
        emit SystemStatusChanged(live);
    }

    // Triggerable action
    function trigger(string calldata actionName) external onlyActuator systemLive {
        // Simulate triggering protocol action (harvest, rebalance, etc.)
        emit ActionTriggered(msg.sender, actionName);
    }
}
