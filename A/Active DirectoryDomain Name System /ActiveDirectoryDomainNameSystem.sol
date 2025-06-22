// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Active Directory DNS System (AD-DNS) — Web3 Edition
contract ADDNS {
    address public admin;

    struct Entry {
        address owner;
        address resolvedAddress;
        string role; // Role attached to the DNS name
    }

    mapping(string => Entry) public records;

    event Registered(string name, address owner, string role);
    event Updated(string name, address newAddress);
    event RoleChanged(string name, string newRole);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyOwner(string memory name) {
        require(records[name].owner == msg.sender, "Not owner");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Register a new DNS entry with role
    function register(string calldata name, address resolved, string calldata role) external {
        require(records[name].owner == address(0), "Already registered");
        records[name] = Entry(msg.sender, resolved, role);
        emit Registered(name, msg.sender, role);
    }

    // Update resolved address
    function updateAddress(string calldata name, address newResolved) external onlyOwner(name) {
        records[name].resolvedAddress = newResolved;
        emit Updated(name, newResolved);
    }

    // Change role
    function updateRole(string calldata name, string calldata newRole) external onlyOwner(name) {
        records[name].role = newRole;
        emit RoleChanged(name, newRole);
    }

    // Resolve domain to address
    function resolve(string calldata name) external view returns (address) {
        return records[name].resolvedAddress;
    }

    // Resolve role for namespace
    function getRole(string calldata name) external view returns (string memory) {
        return records[name].role;
    }

    function getEntry(string calldata name) external view returns (Entry memory) {
        return records[name];
    }
}
