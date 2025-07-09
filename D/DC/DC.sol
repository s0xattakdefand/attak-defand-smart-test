// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DOMAIN CONTROLLER
 *
 * Manages a set of named “domains,” each with its own admin who can
 * authorize or revoke user access within that domain. Provides
 * on-chain authentication and authorization checks.
 */

contract DomainController {
    /// The global contract owner (can register new domains)
    address public owner;

    /// Mapping from domain name to its designated admin
    mapping(string => address) public domainAdmin;

    /// Per-domain authorization: domain => (user => authorized?)
    mapping(string => mapping(address => bool)) public isAuthorized;

    /// Events for audit logging
    event DomainRegistered(string indexed domain, address indexed admin);
    event DomainAdminChanged(string indexed domain, address indexed oldAdmin, address indexed newAdmin);
    event UserAuthorized(string indexed domain, address indexed user);
    event UserRevoked(string indexed domain, address indexed user);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyDomainAdmin(string calldata domain) {
        require(msg.sender == domainAdmin[domain], "Only domain admin");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// Transfer the global owner role
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }

    /// Register a new domain and assign its admin
    function registerDomain(string calldata domain, address admin_) external onlyOwner {
        require(domainAdmin[domain] == address(0), "Domain already exists");
        require(admin_ != address(0), "Admin zero address");
        domainAdmin[domain] = admin_;
        emit DomainRegistered(domain, admin_);
    }

    /// Change an existing domain's admin
    function changeDomainAdmin(string calldata domain, address newAdmin) external onlyOwner {
        require(domainAdmin[domain] != address(0), "Unknown domain");
        require(newAdmin != address(0), "New admin zero address");
        address old = domainAdmin[domain];
        domainAdmin[domain] = newAdmin;
        emit DomainAdminChanged(domain, old, newAdmin);
    }

    /// Domain admin grants a user access within their domain
    function authorizeUser(string calldata domain, address user) external onlyDomainAdmin(domain) {
        require(!isAuthorized[domain][user], "Already authorized");
        isAuthorized[domain][user] = true;
        emit UserAuthorized(domain, user);
    }

    /// Domain admin revokes a user's access within their domain
    function revokeUser(string calldata domain, address user) external onlyDomainAdmin(domain) {
        require(isAuthorized[domain][user], "Not authorized");
        isAuthorized[domain][user] = false;
        emit UserRevoked(domain, user);
    }

    /// Check if a user is authorized in a domain
    function checkAuthorization(string calldata domain, address user) external view returns (bool) {
        return isAuthorized[domain][user];
    }
}
