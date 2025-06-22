// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommunicateP {
    address public admin;

    // Mapping of allowed communication pairs
    mapping(address => mapping(address => bool)) public allowlist;

    event CommunicationAllowed(address indexed from, address indexed to);
    event CommunicationRevoked(address indexed from, address indexed to);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Admin sets communication permission
    function allow(address from, address to) external onlyAdmin {
        allowlist[from][to] = true;
        emit CommunicationAllowed(from, to);
    }

    function revoke(address from, address to) external onlyAdmin {
        allowlist[from][to] = false;
        emit CommunicationRevoked(from, to);
    }

    // Predicate function
    function canCommunicate(address from, address to) external view returns (bool) {
        return allowlist[from][to];
    }

    // Optional: enforcer modifier for integrating contracts
    modifier onlyIfAllowed(address to) {
        require(allowlist[msg.sender][to], "Not allowed to communicate");
        _;
    }
}
