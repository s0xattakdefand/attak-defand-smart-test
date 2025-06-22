// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ZeroizationController — Secure Role, Module, and Secret Wipe System
contract ZeroizationController {
    address public owner;
    address public logicModule;
    bool public active;

    mapping(address => bool) public authorizedUsers;
    mapping(bytes32 => bool) public usedSecrets;
    bytes32 public secretHash;

    event RoleGranted(address indexed user);
    event RoleRevoked(address indexed user);
    event SecretCommitted(bytes32 indexed hash);
    event SecretZeroized();
    event ModuleCleared(address indexed module);
    event ContractDeactivated(address by);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyActive() {
        require(active, "Inactive");
        _;
    }

    constructor(bytes32 _secretHash) {
        owner = msg.sender;
        active = true;
        secretHash = _secretHash;
    }

    /// ✅ Grant and revoke roles
    function grantRole(address user) external onlyOwner onlyActive {
        authorizedUsers[user] = true;
        emit RoleGranted(user);
    }

    function revokeRole(address user) external onlyOwner {
        authorizedUsers[user] = false;
        emit RoleRevoked(user);
    }

    /// ✅ Secret commit/reveal simulation (used once)
    function useSecret(string memory secret, bytes32 salt) external onlyActive {
        bytes32 hash = keccak256(abi.encodePacked(secret, salt));
        require(hash == secretHash, "Invalid secret");
        require(!usedSecrets[hash], "Secret already used");

        usedSecrets[hash] = true;
    }

    function zeroizeSecret() external onlyOwner {
        secretHash = bytes32(0);
        emit SecretZeroized();
    }

    /// ✅ Clear linked module (e.g., delegatecall targets)
    function clearModule() external onlyOwner {
        emit ModuleCleared(logicModule);
        logicModule = address(0);
    }

    /// ✅ Disable contract globally
    function deactivateContract() external onlyOwner {
        active = false;
        logicModule = address(0);
        secretHash = bytes32(0);
        emit ContractDeactivated(msg.sender);
    }

    function isAuthorized(address user) external view returns (bool) {
        return authorizedUsers[user];
    }
}
