// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Code Injection, Ledger Manipulation
/// Defense Types: Registry Control, Role-Based Ledger Posting

contract AccountingNumberLedger {
    address public admin;

    enum Role { NONE, ACCOUNTANT, AUDITOR }

    struct CodeInfo {
        string description;
        bool active;
    }

    mapping(address => Role) public roles;
    mapping(uint256 => CodeInfo) public accountingNumbers;

    event LedgerEntry(
        address indexed actor,
        uint256 accountingNumber,
        string description,
        uint256 amount,
        Role role
    );

    event AttackDetected(address attacker, string reason);
    event RoleAssigned(address indexed user, Role role);
    event CodeRegistered(uint256 code, string description);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
        roles[msg.sender] = Role.ACCOUNTANT;
    }

    /// DEFENSE: Admin registers allowed accounting numbers
    function registerAccountingNumber(uint256 code, string calldata description) external onlyAdmin {
        accountingNumbers[code] = CodeInfo(description, true);
        emit CodeRegistered(code, description);
    }

    /// DEFENSE: Admin assigns roles
    function assignRole(address user, Role role) external onlyAdmin {
        roles[user] = role;
        emit RoleAssigned(user, role);
    }

    /// DEFENSE: Post a tagged transaction entry
    function postLedgerEntry(uint256 code, uint256 amount) external {
        Role userRole = roles[msg.sender];
        if (userRole == Role.NONE) {
            emit AttackDetected(msg.sender, "Unauthorized poster");
            revert("No permission");
        }

        CodeInfo memory info = accountingNumbers[code];
        if (!info.active) {
            emit AttackDetected(msg.sender, "Unregistered accounting number");
            revert("Invalid code");
        }

        emit LedgerEntry(msg.sender, code, info.description, amount, userRole);
    }

    /// ATTACK Simulation: Use fake accounting number
    function attackFakeCode(uint256 fakeCode, uint256 amount) external {
        emit AttackDetected(msg.sender, "Fake accounting number used");
        revert("Simulated attack");
    }

    /// View role and code
    function getRole(address user) external view returns (Role) {
        return roles[user];
    }

    function getAccountingInfo(uint256 code) external view returns (string memory desc, bool active) {
        CodeInfo memory info = accountingNumbers[code];
        return (info.description, info.active);
    }
}
