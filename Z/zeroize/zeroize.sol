// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ZeroizationManager — Secure Zeroization of Keys, Roles, and Modules
contract ZeroizationManager {
    address public owner;
    address public delegateModule;
    mapping(address => bool) public roles;
    bytes32 public sharedKeyHash;
    bool public active;

    event RoleAssigned(address indexed user);
    event RoleRevoked(address indexed user);
    event DelegateCleared(address oldModule);
    event KeyZeroized();
    event ContractDeactivated();

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyActive() {
        require(active, "Inactive");
        _;
    }

    constructor(bytes32 _sharedKeyHash) {
        owner = msg.sender;
        sharedKeyHash = _sharedKeyHash;
        active = true;
    }

    /// ✅ Assign operational role
    function assignRole(address user) external onlyOwner onlyActive {
        roles[user] = true;
        emit RoleAssigned(user);
    }

    /// ✅ Zeroization: revoke role
    function revokeRole(address user) external onlyOwner {
        roles[user] = false;
        emit RoleRevoked(user);
    }

    /// ✅ Zeroization: wipe stored secret (only hash stored)
    function zeroizeKey() external onlyOwner {
        sharedKeyHash = bytes32(0);
        emit KeyZeroized();
    }

    /// ✅ Zeroization: clear module address
    function clearDelegateModule() external onlyOwner {
        emit DelegateCleared(delegateModule);
        delegateModule = address(0);
    }

    /// ✅ Full contract deactivation (Zero Trust + Fail-Safe)
    function deactivateContract() external onlyOwner {
        active = false;
        delegateModule = address(0);
        sharedKeyHash = bytes32(0);
        emit ContractDeactivated();
    }

    /// Example logic (can only run if active)
    function execute(bytes calldata data) external onlyActive {
        require(roles[msg.sender], "Not authorized");
        // ... logic ...
    }
}
