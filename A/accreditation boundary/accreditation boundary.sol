// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Credential Leakage, Domain Drift, Spoofed Issuer
/// Defense Types: Boundary ID Tag, Domain Check, Revocation

contract AccreditationBoundarySystem {
    address public rootAdmin;

    struct Accreditation {
        string tag;
        string boundaryId; // e.g., DAO_X, APP_Z
        uint256 issuedAt;
        uint256 expiresAt;
        address issuer;
    }

    mapping(address => Accreditation) public accreditations;
    mapping(address => bool) public trustedIssuers;

    event Accredited(address indexed user, string tag, string boundaryId);
    event Revoked(address indexed user);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyRoot() {
        require(msg.sender == rootAdmin, "Only root");
        _;
    }

    modifier onlyIssuer() {
        require(trustedIssuers[msg.sender], "Not trusted issuer");
        _;
    }

    constructor() {
        rootAdmin = msg.sender;
        trustedIssuers[msg.sender] = true;
    }

    /// DEFENSE: Register trusted issuer
    function registerIssuer(address issuer) external onlyRoot {
        trustedIssuers[issuer] = true;
    }

    /// DEFENSE: Issue boundary-scoped accreditation
    function issueAccreditation(
        address user,
        string calldata tag,
        string calldata boundaryId,
        uint256 ttl
    ) external onlyIssuer {
        accreditations[user] = Accreditation(tag, boundaryId, block.timestamp, block.timestamp + ttl, msg.sender);
        emit Accredited(user, tag, boundaryId);
    }

    /// DEFENSE: Enforce domain boundary
    function validateBoundary(address user, string calldata requiredBoundary) external view returns (bool) {
        Accreditation memory acc = accreditations[user];
        if (block.timestamp > acc.expiresAt || acc.expiresAt == 0) return false;
        return keccak256(bytes(acc.boundaryId)) == keccak256(bytes(requiredBoundary));
    }

    /// ATTACK Simulation: Use wrong-boundary credential
    function attackCrossBoundaryAccess(string calldata fakeBoundary) external {
        Accreditation memory acc = accreditations[msg.sender];
        if (keccak256(bytes(acc.boundaryId)) != keccak256(bytes(fakeBoundary))) {
            emit AttackDetected(msg.sender, "Cross-boundary spoof attempt");
            revert("Invalid boundary scope");
        }
    }

    /// Revoke accreditation
    function revoke(address user) external onlyIssuer {
        delete accreditations[user];
        emit Revoked(user);
    }

    function getAccreditation(address user) external view returns (
        string memory tag,
        string memory boundaryId,
        uint256 expiresAt
    ) {
        Accreditation memory acc = accreditations[user];
        return (acc.tag, acc.boundaryId, acc.expiresAt);
    }
}
