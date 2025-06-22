// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Unauthorized Access, Access Authority Hijack, Overbroad Authority Assignment
/// Defense Types: Authority Registry, Per-Function Checks, Logging

contract AccessAuthorityManager {
    address public admin;

    mapping(address => bool) public isAccessAuthority;
    mapping(address => mapping(string => bool)) public permissionGrants; // user => permission => allowed

    event AuthorityAssigned(address indexed authority);
    event PermissionGranted(address indexed user, string permission);
    event AccessUsed(address indexed user, string permission);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    modifier hasAccess(string memory permission) {
        if (!permissionGrants[msg.sender][permission]) {
            emit AttackDetected(msg.sender, "Unauthorized access attempt");
            revert("Access denied");
        }
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// DEFENSE: Assign access authority (trusted assigners)
    function assignAuthority(address authority) external onlyAdmin {
        isAccessAuthority[authority] = true;
        emit AuthorityAssigned(authority);
    }

    /// DEFENSE: Grant permission via access authority
    function grantPermission(address user, string calldata permission) external {
        require(isAccessAuthority[msg.sender], "Not an authorized grantor");
        permissionGrants[user][permission] = true;
        emit PermissionGranted(user, permission);
    }

    /// ATTACK Simulation: Unauthorized permission grant attempt
    function attackGrantPermission(address user, string calldata permission) external {
        permissionGrants[user][permission] = true; // no authority check
        emit AttackDetected(msg.sender, "Fake permission grant attack");
        revert("Unauthorized grant attempt");
    }

    /// DEFENSE: Securely use a permission-bound action
    function useProtectedAction(string calldata permission) external hasAccess(permission) returns (string memory) {
        emit AccessUsed(msg.sender, permission);
        return string(abi.encodePacked("Access granted for: ", permission));
    }

    /// View access status
    function checkAccess(address user, string calldata permission) external view returns (bool) {
        return permissionGrants[user][permission];
    }
}
