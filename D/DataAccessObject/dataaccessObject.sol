// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title Designated Authorizing Official Registry
 * @notice  
 *   Implements the “Designated Authorizing Official” (DAO) concept from NIST SP 800-79-2.
 *   A DAO is a senior organization official authorized to vouch for the reliability of issuers.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can add/remove DAOs and pause/unpause the registry.
 *   • DAO_OFFICER_ROLE: designated authorizing officials who may register and authorize issuers.
 *
 * Issuer Lifecycle:
 *   1. Officer calls `registerIssuer(issuerAddr, metadataURI)` to add a new issuer.
 *   2. Officer calls `authorizeIssuer(issuerAddr)` to mark an issuer as reliable.
 *   3. Officer may call `revokeIssuer(issuerAddr)` to withdraw authorization.
 *
 * References:
 *   NIST SP 800-79-2: Section on Designated Authorizing Official under Digital Identity Guidelines.
 */
contract DAOAuthOfficial is AccessControl, Pausable {
    /// Role for designated authorizing officials
    bytes32 public constant DAO_OFFICER_ROLE = keccak256("DAO_OFFICER_ROLE");

    struct Issuer {
        bool    exists;
        bool    authorized;
        string  metadataURI;    // e.g. DID document, policy URI
        address authorizedBy;   // the DAO officer who last authorized
        uint256 timestamp;      // last authorization timestamp
    }

    /// issuer address ⇒ Issuer record
    mapping(address => Issuer) private _issuers;

    event DAOOfficerAdded(address indexed officer);
    event DAOOfficerRemoved(address indexed officer);
    event IssuerRegistered(address indexed issuer, string metadataURI, address indexed by);
    event IssuerAuthorized(address indexed issuer, address indexed by, uint256 timestamp);
    event IssuerRevoked(address indexed issuer, address indexed by, uint256 timestamp);

    modifier onlyOfficer() {
        require(hasRole(DAO_OFFICER_ROLE, msg.sender), "DAOAuth: not an officer");
        _;
    }

    /// @param admin Address to receive DEFAULT_ADMIN_ROLE
    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Grant the DAO_OFFICER_ROLE to an address
    function addOfficer(address officer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(DAO_OFFICER_ROLE, officer);
        emit DAOOfficerAdded(officer);
    }

    /// @notice Revoke the DAO_OFFICER_ROLE from an address
    function removeOfficer(address officer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(DAO_OFFICER_ROLE, officer);
        emit DAOOfficerRemoved(officer);
    }

    /// @notice Register a new issuer in the system
    function registerIssuer(address issuerAddr, string calldata metadataURI)
        external
        whenNotPaused
        onlyOfficer
    {
        require(issuerAddr != address(0), "DAOAuth: zero address");
        Issuer storage iss = _issuers[issuerAddr];
        require(!iss.exists, "DAOAuth: already registered");
        iss.exists       = true;
        iss.metadataURI  = metadataURI;
        emit IssuerRegistered(issuerAddr, metadataURI, msg.sender);
    }

    /// @notice Authorize a registered issuer as reliable
    function authorizeIssuer(address issuerAddr)
        external
        whenNotPaused
        onlyOfficer
    {
        Issuer storage iss = _issuers[issuerAddr];
        require(iss.exists, "DAOAuth: not registered");
        iss.authorized    = true;
        iss.authorizedBy  = msg.sender;
        iss.timestamp     = block.timestamp;
        emit IssuerAuthorized(issuerAddr, msg.sender, block.timestamp);
    }

    /// @notice Revoke authorization from an issuer
    function revokeIssuer(address issuerAddr)
        external
        whenNotPaused
        onlyOfficer
    {
        Issuer storage iss = _issuers[issuerAddr];
        require(iss.exists, "DAOAuth: not registered");
        require(iss.authorized, "DAOAuth: not authorized");
        iss.authorized    = false;
        iss.authorizedBy  = msg.sender;
        iss.timestamp     = block.timestamp;
        emit IssuerRevoked(issuerAddr, msg.sender, block.timestamp);
    }

    /// @notice Retrieve issuer info
    function getIssuer(address issuerAddr)
        external
        view
        returns (
            bool exists,
            bool authorized,
            string memory metadataURI,
            address authorizedBy,
            uint256 timestamp
        )
    {
        Issuer storage iss = _issuers[issuerAddr];
        return (iss.exists, iss.authorized, iss.metadataURI, iss.authorizedBy, iss.timestamp);
    }

    /// @notice Pause registry actions in emergencies
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause registry actions
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
