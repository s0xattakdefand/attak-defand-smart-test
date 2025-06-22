// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AICRegistry — Attestation Identity Credential verifier & store
contract AICRegistry {
    address public admin;

    struct AIC {
        string role;           // e.g., "zkVerifier", "DAOExec", "KYCUser"
        bytes32 pubkeyHash;    // keccak256(pubkey)
        address subject;
        address issuer;
        uint256 validUntil;
        string uri;            // IPFS/Arweave to full credential
        bool active;
    }

    mapping(address => AIC) public aics;

    event AICIssued(address indexed subject, string role, address indexed issuer);
    event AICRevoked(address indexed subject);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function issueAIC(
        address subject,
        string calldata role,
        bytes32 pubkeyHash,
        string calldata uri,
        uint256 validUntil
    ) external onlyAdmin {
        aics[subject] = AIC(role, pubkeyHash, subject, msg.sender, validUntil, uri, true);
        emit AICIssued(subject, role, msg.sender);
    }

    function revokeAIC(address subject) external onlyAdmin {
        aics[subject].active = false;
        emit AICRevoked(subject);
    }

    function getAIC(address subject) external view returns (AIC memory) {
        return aics[subject];
    }

    function isValid(address subject) external view returns (bool) {
        AIC memory a = aics[subject];
        return a.active && block.timestamp <= a.validUntil;
    }

    function hasRole(address subject, string calldata role) external view returns (bool) {
        AIC memory a = aics[subject];
        return a.active && keccak256(abi.encodePacked(a.role)) == keccak256(abi.encodePacked(role));
    }
}
