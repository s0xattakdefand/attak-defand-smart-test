// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Address Space Identifier (ASID) Registry and Access Manager
contract ASIDManager {
    address public admin;

    // asid => user => permission
    mapping(uint256 => mapping(address => bool)) public hasAccess;

    event AccessGranted(uint256 indexed asid, address indexed user);
    event AccessRevoked(uint256 indexed asid, address indexed user);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyASID(uint256 asid) {
        require(hasAccess[asid][msg.sender], "ASID: No access");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function grantAccess(uint256 asid, address user) external onlyAdmin {
        hasAccess[asid][user] = true;
        emit AccessGranted(asid, user);
    }

    function revokeAccess(uint256 asid, address user) external onlyAdmin {
        hasAccess[asid][user] = false;
        emit AccessRevoked(asid, user);
    }

    // Example: Protected call scoped to an ASID
    function executeScoped(uint256 asid, string calldata command) external onlyASID(asid) {
        // Logic for scoped command execution
        // Example: vault access, DAO command, zk bound access
    }

    function getASID(string calldata namespace) external pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(namespace)));
    }
}
