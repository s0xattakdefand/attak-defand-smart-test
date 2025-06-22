// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AESKWPCommit — Commitment system for AES Key Wrap with Padding
contract AESKWPCommit {
    address public admin;

    struct WrappedData {
        bytes32 wrappedHash;    // keccak256(AES-KWP ciphertext)
        string label;           // e.g., "zkSeed2025"
        address submitter;
        uint256 length;         // original (pre-padding) data length
        bool padded;
        uint256 timestamp;
    }

    WrappedData[] public records;

    event DataWrapped(uint256 indexed id, address indexed submitter, string label, bytes32 wrappedHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function submitWrappedData(
        bytes32 wrappedHash,
        string calldata label,
        uint256 originalLength,
        bool padded
    ) external returns (uint256) {
        records.push(WrappedData(wrappedHash, label, msg.sender, originalLength, padded, block.timestamp));
        uint256 id = records.length - 1;
        emit DataWrapped(id, msg.sender, label, wrappedHash);
        return id;
    }

    function getRecord(uint256 id) external view returns (WrappedData memory) {
        return records[id];
    }

    function totalRecords() external view returns (uint256) {
        return records.length;
    }
}
