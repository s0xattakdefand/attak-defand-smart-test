// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Web3 Actuating Capability Controller
contract ActuationController {
    address public admin;
    mapping(address => bool) public actuators;
    bool public systemLive;

    event ActuationTriggered(address indexed by, string command);
    event ActuatorGranted(address indexed actor);
    event ActuatorRevoked(address indexed actor);
    event SystemStatusChanged(bool isLive);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyActuator() {
        require(actuators[msg.sender], "Not an actuator");
        _;
    }

    modifier systemActive() {
        require(systemLive, "System offline");
        _;
    }

    constructor() {
        admin = msg.sender;
        systemLive = true;
        actuators[msg.sender] = true;
    }

    // Manage actuators
    function grantActuator(address actor) external onlyAdmin {
        actuators[actor] = true;
        emit ActuatorGranted(actor);
    }

    function revokeActuator(address actor) external onlyAdmin {
        delete actuators[actor];
        emit ActuatorRevoked(actor);
    }

    function toggleSystem(bool live) external onlyAdmin {
        systemLive = live;
        emit SystemStatusChanged(live);
    }

    // Actuating capability
    function triggerCommand(string calldata command) external onlyActuator systemActive {
        // Command logic goes here
        emit ActuationTriggered(msg.sender, command);
    }
}
