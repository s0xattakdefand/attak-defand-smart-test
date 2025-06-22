// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Ledger Spoof, Misclassification, Legend Drift
/// Defense Types: Legend Registry, Role Control, Immutable Logs

contract AccountingLegendLedger {
    address public admin;

    enum Role { NONE, ACCOUNTANT, OPERATOR }
    mapping(address => Role) public roles;

    struct LegendCode {
        string name;
        bool active;
    }

    mapping(string => LegendCode) public legendCodes;
    mapping(address => bool) public approvedPosters;

    event LedgerEntry(
        address indexed sender,
        string code,
        string description,
        uint256 amount,
        Role role
    );

    event AttackDetected(address indexed attacker, string reason);
    event LegendRegistered(string code, string name);
    event RoleAssigned(address user, Role role);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
        roles[msg.sender] = Role.ACCOUNTANT;
    }

    /// DEFENSE: Register legend code
    function registerLegendCode(string calldata code, string calldata name) external onlyAdmin {
        legendCodes[code] = LegendCode(name, true);
        emit LegendRegistered(code, name);
    }

    /// DEFENSE: Assign user role
    function assignRole(address user, Role role) external onlyAdmin {
        roles[user] = role;
        emit RoleAssigned(user, role);
    }

    /// DEFENSE: Post ledger entry (accounting tx) with tag enforcement
    function postLedgerEntry(string calldata code, string calldata description, uint256 amount) external {
        Role userRole = roles[msg.sender];
        if (userRole == Role.NONE) {
            emit AttackDetected(msg.sender, "Unauthorized ledger post");
            revert("No role");
        }

        if (!legendCodes[code].active) {
            emit AttackDetected(msg.sender, "Invalid legend code");
            revert("Code not registered");
        }

        emit LedgerEntry(msg.sender, code, description, amount, userRole);
    }

    /// ATTACK Simulation: Post with unregistered tag
    function attackPostInvalidLegend() external {
        emit AttackDetected(msg.sender, "Legend spoof attempt");
        revert("Attack simulated");
    }

    /// View code info
    function getLegendInfo(string calldata code) external view returns (string memory name, bool active) {
        LegendCode memory lc = legendCodes[code];
        return (lc.name, lc.active);
    }

    function getRole(address user) external view returns (Role) {
        return roles[user];
    }
}
