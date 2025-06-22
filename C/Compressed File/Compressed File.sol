// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CompressedDataHandler
/// @notice Handles submission and root verification of compressed calldata
contract CompressedDataHandler {
    address public admin;
    uint256 public constant MAX_DECOMPRESSED_BYTES = 1024;

    mapping(bytes32 => bool) public acceptedRoots;
    mapping(bytes32 => bool) public usedPayloads;

    event CompressedDataProcessed(address indexed sender, bytes32 compressedHash, bytes32 uncompressedRoot);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Admin pre-approves a Merkle root of valid uncompressed data
    function whitelistRoot(bytes32 root) external onlyAdmin {
        acceptedRoots[root] = true;
    }

    /// @notice Submit compressed payload with precomputed root of its uncompressed content
    function submitCompressed(bytes calldata compressedData, bytes32 uncompressedRoot) external {
        bytes32 payloadHash = keccak256(compressedData);
        require(!usedPayloads[payloadHash], "Replay blocked");
        require(acceptedRoots[uncompressedRoot], "Invalid uncompressed root");

        // Simulated gas-bound decompression check
        require(compressedData.length < 256, "Compressed too large");
        // Here, actual decompression would occur off-chain, and root would be recomputed and verified

        usedPayloads[payloadHash] = true;
        emit CompressedDataProcessed(msg.sender, payloadHash, uncompressedRoot);
    }
}
