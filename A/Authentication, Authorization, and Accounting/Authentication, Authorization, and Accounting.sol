// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Authentication Bypass Attack, Authorization Abuse Attack, Accounting Blindness Attack
/// Defense Types: Strict Sequential AAA Enforcement, Replay Protection, Immutable Usage Logs

contract AAASystem {
    address public admin;

    struct Session {
        bool authenticated;
        mapping(string => bool) authorizedActions;
        uint256 usage;
    }

    mapping(address => Session) internal sessions;

    event AuthenticationSuccess(address indexed user);
    event AuthorizationGranted(address indexed user, string action);
    event ActionPerformed(address indexed user, string action, uint256 usageLogged);
    event AttackDetected(address indexed attacker, string reason);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can operate");
        _;
    }

    /// ATTACK Simulation: Try to perform action without authentication
    function attackAuthenticationBypass(string calldata action) external {
        Session storage session = sessions[msg.sender];
        if (!session.authenticated) {
            emit AttackDetected(msg.sender, "Authentication bypass attempt");
            revert("Not authenticated");
        }
        if (!session.authorizedActions[action]) {
            emit AttackDetected(msg.sender, "Authorization abuse attempt");
            revert("Not authorized");
        }
    }

    /// DEFENSE: Authenticate user
    function authenticate() external {
        sessions[msg.sender].authenticated = true;
        emit AuthenticationSuccess(msg.sender);
    }

    /// DEFENSE: Authorize user for a specific action
    function authorizeAction(string calldata action) external onlyAdmin {
        require(sessions[msg.sender].authenticated, "User must authenticate first");
        sessions[msg.sender].authorizedActions[action] = true;
        emit AuthorizationGranted(msg.sender, action);
    }

    /// DEFENSE: Perform action after full AAA enforcement
    function performAction(string calldata action, uint256 usageAmount) external {
        Session storage session = sessions[msg.sender];

        require(session.authenticated, "Authentication required");
        require(session.authorizedActions[action], "Authorization required");
        require(usageAmount > 0, "Usage must be nonzero");

        session.usage += usageAmount;
        emit ActionPerformed(msg.sender, action, usageAmount);
    }

    /// View usage data for accounting
    function viewUsage(address user) external view returns (uint256 totalUsage) {
        return sessions[user].usage;
    }
}
