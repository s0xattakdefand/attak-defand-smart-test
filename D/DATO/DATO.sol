// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * PIV ISSUER AUTHORIZATION DEMO
 * NIST SP 800-79-2 — “Denial of Authorization to Operate; issued by a DAO 
 * to an issuer that is not authorized as being reliable for the issuance 
 * of PIV Cards or Derived PIV Credentials.”
 *
 * SECTION 1 — VulnerableIssuerRegistry (⚠️ insecure)
 *   • Anyone can add or remove issuers.
 *   • No DAO control or immutable audit of revocations.
 *
 * SECTION 2 — SecureIssuerDAORegistry (✅ hardened)
 *   • Only the DAO (owner) can authorize or revoke issuers.
 *   • Emits events for authorizations and denials.
 *   • Provides a sample `issueCard` guard that only lets authorized
 *     issuers operate.
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — VulnerableIssuerRegistry
/// -------------------------------------------------------------------------
contract VulnerableIssuerRegistry {
    mapping(address => bool) public authorized;

    event IssuerAuthorizationSet(address indexed issuer, bool authorized);

    /// Anyone can call to grant or revoke any issuer.
    function setAuthorization(address issuer, bool auth) external {
        authorized[issuer] = auth;
        emit IssuerAuthorizationSet(issuer, auth);
    }

    /// Only “authorized” issuers may issue cards—but authorization itself
    /// can be tampered with by any caller.
    function issueCard(address subject) external view returns (bool) {
        require(authorized[msg.sender], "Not authorized issuer");
        // ... issuance logic would go here ...
        return true;
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — SecureIssuerDAORegistry
/// -------------------------------------------------------------------------
contract SecureIssuerDAORegistry {
    /// The DAO that controls issuer authorizations
    address public dao;

    /// Mapping of trusted issuers
    mapping(address => bool) public authorized;

    event DAOChanged(address indexed oldDAO, address indexed newDAO);
    event IssuerAuthorized(address indexed issuer);
    event IssuerRevoked(address indexed issuer);

    modifier onlyDAO() {
        require(msg.sender == dao, "Only DAO");
        _;
    }

    constructor() {
        dao = msg.sender;
    }

    /// DAO can transfer governance to a new DAO
    function changeDAO(address newDAO) external onlyDAO {
        require(newDAO != address(0), "Zero address");
        emit DAOChanged(dao, newDAO);
        dao = newDAO;
    }

    /// DAO authorizes a new issuer
    function authorizeIssuer(address issuer) external onlyDAO {
        authorized[issuer] = true;
        emit IssuerAuthorized(issuer);
    }

    /// DAO revokes an issuer’s authorization (Denial of Authorization to Operate)
    function revokeIssuer(address issuer) external onlyDAO {
        authorized[issuer] = false;
        emit IssuerRevoked(issuer);
    }

    /// Sample guard: only authorized issuers can issue cards
    function issueCard(address subject) external view returns (bool) {
        require(authorized[msg.sender], "Issuer not authorized");
        // ... issuance logic would go here ...
        return true;
    }
}
