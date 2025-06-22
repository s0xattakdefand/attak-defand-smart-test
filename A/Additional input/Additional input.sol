// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Additional Input Example in Hash Commitment or KDF
contract AdditionalInputHandler {
    function deriveCommitment(
        address user,
        string calldata domain,
        uint256 timestamp,
        string calldata action,
        bytes32 secret
    ) external pure returns (bytes32) {
        bytes32 additionalInput = keccak256(abi.encodePacked(user, domain, timestamp, action));
        return keccak256(abi.encodePacked(secret, additionalInput));
    }

    function verifyCommitment(
        bytes32 expectedCommit,
        address user,
        string calldata domain,
        uint256 timestamp,
        string calldata action,
        bytes32 secret
    ) external pure returns (bool) {
        bytes32 additionalInput = keccak256(abi.encodePacked(user, domain, timestamp, action));
        return expectedCommit == keccak256(abi.encodePacked(secret, additionalInput));
    }
}
