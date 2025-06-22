// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AES-GCM Validator — Hybrid offchain AES, onchain integrity validation
contract AESGCMValidator {
    struct GCMRecord {
        bytes32 commitment; // hash of (ciphertext || tag || aad)
        bool validated;
        string decrypted; // optional offchain revealed plaintext
    }

    address public admin;
    mapping(address => GCMRecord[]) public records;

    event GCMCommitted(address indexed user, uint256 indexed index, bytes32 commitment);
    event GCMValidated(address indexed user, uint256 indexed index, string plaintext);

    constructor() {
        admin = msg.sender;
    }

    /// Commit AES-GCM (ciphertext + tag + AAD) hash
    function commitGCM(bytes32 commitment) external {
        records[msg.sender].push(GCMRecord(commitment, false, ""));
        emit GCMCommitted(msg.sender, records[msg.sender].length - 1, commitment);
    }

    /// Reveal decrypted plaintext and verify
    function validateGCM(
        uint256 index,
        bytes calldata ciphertext,
        bytes16 tag,
        bytes calldata aad,
        string calldata decrypted
    ) external {
        GCMRecord storage r = records[msg.sender][index];
        require(!r.validated, "Already validated");

        bytes32 computed = keccak256(abi.encodePacked(ciphertext, tag, aad));
        require(computed == r.commitment, "AES-GCM validation failed");

        r.validated = true;
        r.decrypted = decrypted;
        emit GCMValidated(msg.sender, index, decrypted);
    }

    function getRecord(address user, uint256 index) external view returns (GCMRecord memory) {
        return records[user][index];
    }
}
