// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Complexity Downgrade, Role Misalignment, Open Surface Exposure
/// Defense Types: Complexity Level Enforcement, Caller Role Matching, Logging

contract AccessComplexityManager {
    enum Complexity { LOW, MEDIUM, HIGH }

    address public admin;
    mapping(address => Complexity) public userComplexityLevel;

    event ComplexityAssigned(address indexed user, Complexity level);
    event AccessGranted(address indexed user, string action, Complexity required);
    event AttackDetected(address indexed user, string reason);

    constructor() {
        admin = msg.sender;
        userComplexityLevel[admin] = Complexity.HIGH;
        emit ComplexityAssigned(admin, Complexity.HIGH);
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    /// DEFENSE: Assign access complexity level to a user
    function assignComplexity(address user, Complexity level) external onlyAdmin {
        userComplexityLevel[user] = level;
        emit ComplexityAssigned(user, level);
    }

    /// ATTACK Simulation: Access low-complexity target without any permission
    function attackLowComplexityAccess() external returns (string memory) {
        emit AttackDetected(msg.sender, "Unauthorized low-complexity action triggered");
        return "Attack simulated";
    }

    /// DEFENSE: Medium-complexity protected action
    function mediumComplexityAction() external returns (string memory) {
        if (userComplexityLevel[msg.sender] < Complexity.MEDIUM) {
            emit AttackDetected(msg.sender, "Complexity mismatch for MEDIUM access");
            revert("Insufficient access complexity");
        }
        emit AccessGranted(msg.sender, "MediumAction", Complexity.MEDIUM);
        return "Medium complexity action performed";
    }

    /// DEFENSE: High-complexity protected action
    function highComplexityAction() external returns (string memory) {
        if (userComplexityLevel[msg.sender] < Complexity.HIGH) {
            emit AttackDetected(msg.sender, "Complexity mismatch for HIGH access");
            revert("Insufficient access complexity");
        }
        emit AccessGranted(msg.sender, "HighAction", Complexity.HIGH);
        return "High complexity action performed";
    }

    /// View user level
    function getUserLevel(address user) external view returns (Complexity) {
        return userComplexityLevel[user];
    }
}
