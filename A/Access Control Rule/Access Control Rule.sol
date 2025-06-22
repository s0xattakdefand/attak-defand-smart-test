// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Core Access Control Rule Engine (ACR)
contract AccessControlRule {
    address public admin;

    struct Rule {
        bool allowed;
        uint256 expiresAt; // 0 = no expiry
    }

    mapping(address => mapping(string => Rule)) public rules;

    event RuleSet(address indexed user, string action, bool allowed, uint256 expiresAt);
    event RuleRevoked(address indexed user, string action);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Set rule for user and action (optional expiry)
    function setRule(address user, string calldata action, bool allowed, uint256 ttl) external onlyAdmin {
        rules[user][action] = Rule(allowed, ttl > 0 ? block.timestamp + ttl : 0);
        emit RuleSet(user, action, allowed, rules[user][action].expiresAt);
    }

    /// Revoke rule
    function revokeRule(address user, string calldata action) external onlyAdmin {
        delete rules[user][action];
        emit RuleRevoked(user, action);
    }

    /// Modifier to enforce ACR
    modifier onlyAllowed(string memory action) {
        Rule memory r = rules[msg.sender][action];
        require(r.allowed, "Access denied");
        require(r.expiresAt == 0 || block.timestamp < r.expiresAt, "Rule expired");
        _;
    }

    /// DEFENSED ACTION
    function executeAction(string calldata action) external onlyAllowed(action) {
        // Do protected logic here
    }

    /// ATTACK: Simulate bypass attempt
    function attackBypass(string calldata action) external {
        emit AttackDetected(msg.sender, "Unauthorized ACR bypass attempt");
        revert("Blocked by ACR");
    }

    /// View rule
    function getRule(address user, string calldata action) external view returns (Rule memory) {
        return rules[user][action];
    }
}
