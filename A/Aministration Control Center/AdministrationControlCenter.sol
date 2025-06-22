// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Admin Hijack, Overbroad Delegation, Missing Emergency Controls
/// Defense Types: Multi-tier Role Control, Strict Role Access, Emergency Pausing

contract AdministrationControlCenter {
    address public rootAdmin;
    address public operatorAdmin;
    address public emergencyAdmin;

    bool public isSystemPaused;

    event AdminAssigned(string role, address newAdmin);
    event SystemPaused(address indexed triggeredBy);
    event SystemResumed(address indexed triggeredBy);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyRoot() {
        require(msg.sender == rootAdmin, "Only root admin");
        _;
    }

    modifier onlyOperator() {
        require(msg.sender == operatorAdmin, "Only operator admin");
        _;
    }

    modifier onlyEmergency() {
        require(msg.sender == emergencyAdmin, "Only emergency admin");
        _;
    }

    modifier notPaused() {
        require(!isSystemPaused, "System is paused");
        _;
    }

    constructor(address _operator, address _emergency) {
        rootAdmin = msg.sender;
        operatorAdmin = _operator;
        emergencyAdmin = _emergency;
    }

    /// DEFENSE: Assign new operator
    function assignOperator(address newOperator) external onlyRoot {
        operatorAdmin = newOperator;
        emit AdminAssigned("OPERATOR", newOperator);
    }

    /// DEFENSE: Assign new emergency admin
    function assignEmergencyAdmin(address newEmergency) external onlyRoot {
        emergencyAdmin = newEmergency;
        emit AdminAssigned("EMERGENCY", newEmergency);
    }

    /// DEFENSE: Emergency pause trigger
    function triggerEmergencyPause() external onlyEmergency {
        isSystemPaused = true;
        emit SystemPaused(msg.sender);
    }

    /// DEFENSE: Resume system from emergency
    function resumeSystem() external onlyRoot {
        isSystemPaused = false;
        emit SystemResumed(msg.sender);
    }

    /// ATTACK Simulation: Unauthorized admin role change
    function attackUnauthorizedAdminChange(address fakeOperator) external {
        operatorAdmin = fakeOperator;
        emit AttackDetected(msg.sender, "Unauthorized operator override attempt");
        revert("Not allowed");
    }

    /// Example protected operation
    function performGovernanceAction() external onlyOperator notPaused returns (string memory) {
        return "Governance action executed successfully.";
    }
}
