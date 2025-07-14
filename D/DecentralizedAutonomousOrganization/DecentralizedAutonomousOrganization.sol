// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DESIGNATED AUTHORIZING OFFICIAL (DAO) ISSUER RELIABILITY REGISTRY
 * NIST SP 800-79-2 — “A senior organization official that has been given
 * the authorization to authorize the reliability of an issuer.”
 *
 * This contract allows:
 *  • The contract owner to appoint a Designated Authorizing Official (DAO).
 *  • The DAO to mark issuers as reliable (or revoke reliability).
 *  • Anyone to query an issuer’s reliability status.
 *  • Full audit via events.
 */

contract DAOIssuerReliability {
    address public owner;
    address public designatedAuthorizingOfficial;

    mapping(address => bool) public reliableIssuers;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OfficialAssigned(address indexed previousOfficial, address indexed newOfficial);
    event IssuerReliabilityAuthorized(address indexed issuer, address indexed by);
    event IssuerReliabilityRevoked(address indexed issuer, address indexed by);

    modifier onlyOwner() {
        require(msg.sender == owner, "DAOIR: caller is not owner");
        _;
    }

    modifier onlyOfficial() {
        require(msg.sender == designatedAuthorizingOfficial, "DAOIR: caller is not DAO");
        _;
    }

    constructor() {
        owner = msg.sender;
        designatedAuthorizingOfficial = msg.sender;
        emit OwnershipTransferred(address(0), owner);
        emit OfficialAssigned(address(0), designatedAuthorizingOfficial);
    }

    /// @notice Transfer contract ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "DAOIR: new owner is zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Assign a new Designated Authorizing Official (DAO)
    function assignOfficial(address newOfficial) external onlyOwner {
        require(newOfficial != address(0), "DAOIR: new official is zero address");
        emit OfficialAssigned(designatedAuthorizingOfficial, newOfficial);
        designatedAuthorizingOfficial = newOfficial;
    }

    /// @notice DAO marks an issuer as reliable
    function authorizeIssuer(address issuer) external onlyOfficial {
        require(!reliableIssuers[issuer], "DAOIR: issuer already authorized");
        reliableIssuers[issuer] = true;
        emit IssuerReliabilityAuthorized(issuer, msg.sender);
    }

    /// @notice DAO revokes an issuer’s reliability
    function revokeIssuer(address issuer) external onlyOfficial {
        require(reliableIssuers[issuer], "DAOIR: issuer not authorized");
        reliableIssuers[issuer] = false;
        emit IssuerReliabilityRevoked(issuer, msg.sender);
    }

    /// @notice Check whether an issuer is reliable
    function isIssuerReliable(address issuer) external view returns (bool) {
        return reliableIssuers[issuer];
    }
}
