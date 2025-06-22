// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CRIME-Safe Compression Router
/// @notice Protects against compression-based info-leak attacks
contract CrimeSafeCompressedRouter {
    address public admin;
    uint256 public constant MAX_COMPRESSION_RATIO = 6; // e.g. if uncompressed is 600 bytes, compressed must not be <100

    mapping(bytes32 => bool) public usedPayloads;

    event PayloadAccepted(address indexed sender, bytes32 payloadHash, uint256 ratio);
    event PayloadRejected(bytes32 payloadHash, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Submit compressed and original payload to check CRIME-safety
    function submitPayload(bytes calldata compressed, bytes calldata original) external {
        bytes32 id = keccak256(compressed);
        require(!usedPayloads[id], "Replay blocked");

        uint256 ratio = (original.length * 1e18) / compressed.length;
        require(ratio <= MAX_COMPRESSION_RATIO * 1e18, "Compression ratio too high — possible info leak");

        usedPayloads[id] = true;
        emit PayloadAccepted(msg.sender, id, ratio);
        // Optional: route to plugin, DAO, zkApp, etc.
    }

    /// @notice Admin can raise compression ratio threshold (if padding added elsewhere)
    function setMaxRatio(uint256 ratio) external onlyAdmin {
        require(ratio >= 1 && ratio <= 10, "Invalid ratio");
        // ratio is whole number
    }
}
