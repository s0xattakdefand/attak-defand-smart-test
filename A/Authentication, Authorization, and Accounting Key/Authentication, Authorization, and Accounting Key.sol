// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Authentication Bypass Attack, Authorization Drift Attack, Accounting Evasion Attack
/// Defense Types: Triple-Layer Binding (Authentication+Authorization+Accounting), Strict Validation, Audit Trail Enforcement

contract AAAKeySystem {
    address public admin;

    mapping(address => bool) public authenticatedUsers;
    mapping(address => mapping(string => bool)) public authorizedActions; // user => action => authorized
    mapping(address => uint256) public userUsageAccounting; // tracks resource usage

    event AuthenticationSuccessful(address indexed user);
    event AuthorizationGranted(address indexed user, string action);
    event AccountingLogged(address indexed user, uint256 amountUsed);
    event AttackDetected(address indexed attacker, string reason);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    /// ATTACK Simulation: Skip authentication and try to act
    function attackBypassAuthentication(string calldata action) external {
        if (!authenticatedUsers[msg.sender]) {
            emit AttackDetected(msg.sender, "Authentication bypass attempt detected");
            revert("Not authenticated");
        }
        if (!authorizedActions[msg.sender][action]) {
            emit AttackDetected(msg.sender, "Authorization drift attempt detected");
            revert("Not authorized");
        }
    }

    /// DEFENSE: Admin authenticates a user
    function authenticateUser(address user) external onlyAdmin {
        authenticatedUsers[user] = true;
        emit AuthenticationSuccessful(user);
    }

    /// DEFENSE: Admin grants specific action authorization
    function authorizeUserAction(address user, string calldata action) external onlyAdmin {
        require(authenticatedUsers[user], "User must be authenticated first");
        authorizedActions[user][action] = true;
        emit AuthorizationGranted(user, action);
    }

    /// DEFENSE: Secure action execution with full AAA enforcement
    function performActionWithAccounting(string calldata action, uint256 usageAmount) external {
        require(authenticatedUsers[msg.sender], "Authentication failed");
        require(authorizedActions[msg.sender][action], "Authorization failed");
        require(usageAmount > 0, "Invalid accounting amount");

        // Log accounting
        userUsageAccounting[msg.sender] += usageAmount;
        emit AccountingLogged(msg.sender, usageAmount);
    }

    /// View user accounting usage
    function viewAccountingUsage(address user) external view returns (uint256 totalUsage) {
        return userUsageAccounting[user];
    }
}
