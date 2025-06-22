// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: AA Impersonation, Scope Drift, Unrevoked Credential
/// Defense Types: Registry, Scoped Issuance, Revocation Logging

contract AccreditingAuthoritySystem {
    address public rootAdmin;

    struct Credential {
        string tag;            // e.g., "VERIFIED_CONTRIBUTOR"
        string domain;         // e.g., "DAO_X"
        address issuer;
        uint256 issuedAt;
        uint256 expiresAt;
    }

    mapping(address => Credential) public credentials;
    mapping(address => bool) public isAccreditingAuthority;

    event AuthorityAdded(address indexed authority);
    event CredentialIssued(address indexed user, string tag, string domain);
    event CredentialRevoked(address indexed user);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyRoot() {
        require(msg.sender == rootAdmin, "Only root admin");
        _;
    }

    modifier onlyAuthority() {
        require(isAccreditingAuthority[msg.sender], "Not an accrediting authority");
        _;
    }

    constructor() {
        rootAdmin = msg.sender;
        isAccreditingAuthority[msg.sender] = true;
        emit AuthorityAdded(msg.sender);
    }

    /// DEFENSE: Register new accrediting authority
    function addAuthority(address authority) external onlyRoot {
        isAccreditingAuthority[authority] = true;
        emit AuthorityAdded(authority);
    }

    /// DEFENSE: Issue credential within domain
    function issueCredential(address user, string calldata tag, string calldata domain, uint256 ttl) external onlyAuthority {
        credentials[user] = Credential(tag, domain, msg.sender, block.timestamp, block.timestamp + ttl);
        emit CredentialIssued(user, tag, domain);
    }

    /// DEFENSE: Revoke issued credential
    function revokeCredential(address user) external onlyAuthority {
        delete credentials[user];
        emit CredentialRevoked(user);
    }

    /// ATTACK SIMULATION: Unauthorized credential issuance
    function attackFakeCredential(address user, string calldata tag) external {
        credentials[user] = Credential(tag, "FAKE_DOMAIN", msg.sender, block.timestamp, block.timestamp + 30 days);
        emit AttackDetected(msg.sender, "Fake authority issued credential");
        revert("Attack simulated");
    }

    /// VIEW: Validate domain-bound credential
    function validateCredential(address user, string calldata requiredDomain) external view returns (bool) {
        Credential memory cred = credentials[user];
        return (
            keccak256(bytes(cred.domain)) == keccak256(bytes(requiredDomain)) &&
            cred.expiresAt >= block.timestamp
        );
    }

    function getCredential(address user) external view returns (string memory tag, string memory domain, address issuer, uint256 expiresAt) {
        Credential memory cred = credentials[user];
        return (cred.tag, cred.domain, cred.issuer, cred.expiresAt);
    }
}
