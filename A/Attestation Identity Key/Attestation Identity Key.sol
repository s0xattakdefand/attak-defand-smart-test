// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AIKRegistry — Register and validate Attestation Identity Keys
contract AIKRegistry {
    address public admin;

    struct AIK {
        address subject;         // entity using the AIK
        string role;             // e.g., "zkAgent", "TEE", "DAO_Relayer"
        bytes32 pubkeyHash;      // keccak256(publicKey)
        string uri;              // metadata or certificate pointer
        uint256 validUntil;
        bool active;
    }

    mapping(address => AIK) public aiks;

    event AIKRegistered(address indexed subject, string role, bytes32 pubkeyHash);
    event AIKRevoked(address indexed subject);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerAIK(
        address subject,
        string calldata role,
        bytes32 pubkeyHash,
        string calldata uri,
        uint256 validUntil
    ) external onlyAdmin {
        aiks[subject] = AIK(subject, role, pubkeyHash, uri, validUntil, true);
        emit AIKRegistered(subject, role, pubkeyHash);
    }

    function revokeAIK(address subject) external onlyAdmin {
        aiks[subject].active = false;
        emit AIKRevoked(subject);
    }

    function getAIK(address subject) external view returns (AIK memory) {
        return aiks[subject];
    }

    function isValid(address subject) external view returns (bool) {
        AIK memory a = aiks[subject];
        return a.active && block.timestamp <= a.validUntil;
    }

    function verifyPubkeyHash(address subject, bytes32 candidateHash) external view returns (bool) {
        return aiks[subject].pubkeyHash == candidateHash;
    }
}
