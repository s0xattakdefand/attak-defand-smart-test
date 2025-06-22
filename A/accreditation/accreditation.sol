// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Forged Accreditation, Drifted Status, Spoofed Issuer
/// Defense Types: Issuer Registry, Expiry Check, Signature Audit

contract AccreditationAuthority {
    address public rootAdmin;

    struct Accreditation {
        address issuer;
        string tag;
        uint256 issuedAt;
        uint256 expiresAt;
    }

    mapping(address => Accreditation) public accreditations;
    mapping(address => bool) public trustedIssuers;

    event Accredited(address indexed user, string tag, uint256 expiresAt);
    event Revoked(address indexed user);
    event IssuerRegistered(address indexed issuer);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyRoot() {
        require(msg.sender == rootAdmin, "Only root admin");
        _;
    }

    modifier onlyIssuer() {
        require(trustedIssuers[msg.sender], "Not a registered issuer");
        _;
    }

    constructor() {
        rootAdmin = msg.sender;
        trustedIssuers[msg.sender] = true;
        emit IssuerRegistered(msg.sender);
    }

    /// DEFENSE: Register a trusted issuer
    function registerIssuer(address issuer) external onlyRoot {
        trustedIssuers[issuer] = true;
        emit IssuerRegistered(issuer);
    }

    /// DEFENSE: Issue an accreditation with tag + expiry
    function issueAccreditation(address user, string calldata tag, uint256 ttl) external onlyIssuer {
        uint256 expiry = block.timestamp + ttl;
        accreditations[user] = Accreditation(msg.sender, tag, block.timestamp, expiry);
        emit Accredited(user, tag, expiry);
    }

    /// DEFENSE: Revoke
    function revoke(address user) external onlyIssuer {
        delete accreditations[user];
        emit Revoked(user);
    }

    /// ATTACK Simulation: Non-issuer attempts issuance
    function attackIssueFakeAccreditation(address user, string calldata tag) external {
        accreditations[user] = Accreditation(msg.sender, tag, block.timestamp, block.timestamp + 30 days);
        emit AttackDetected(msg.sender, "Fake issuer attempted accreditation");
        revert("Attack simulated");
    }

    /// View accreditation details
    function getAccreditation(address user) external view returns (string memory tag, bool active) {
        Accreditation memory a = accreditations[user];
        bool isActive = (block.timestamp <= a.expiresAt && a.expiresAt != 0);
        return (a.tag, isActive);
    }

    /// Validate accreditation with tag
    function validateAccreditation(address user, string calldata requiredTag) external view returns (bool) {
        Accreditation memory a = accreditations[user];
        return (keccak256(bytes(a.tag)) == keccak256(bytes(requiredTag)) && block.timestamp <= a.expiresAt);
    }
}
