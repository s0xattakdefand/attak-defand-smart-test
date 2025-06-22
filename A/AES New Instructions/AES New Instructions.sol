// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AESNICommit — Verifies AES-NI offchain work by logging commitment hashes
contract AESNICommit {
    address public admin;

    struct AESNIEntry {
        bytes32 hash;         // keccak256(AES-NI ciphertext)
        string algorithm;     // e.g., AES-128-GCM, AES-KW
        string label;         // metadata label (e.g., zkBlob2025)
        address submitter;
        uint256 timestamp;
    }

    AESNIEntry[] public entries;

    event AESNICommitted(uint256 indexed id, address indexed submitter, bytes32 hash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function commitAESNI(bytes32 hash, string calldata algorithm, string calldata label) external returns (uint256) {
        entries.push(AESNIEntry(hash, algorithm, label, msg.sender, block.timestamp));
        uint256 id = entries.length - 1;
        emit AESNICommitted(id, msg.sender, hash);
        return id;
    }

    function getEntry(uint256 id) external view returns (AESNIEntry memory) {
        return entries[id];
    }

    function totalEntries() external view returns (uint256) {
        return entries.length;
    }
}
