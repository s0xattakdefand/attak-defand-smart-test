// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConditioningFunctionDemo — Demonstrates secure conditioning of input for hashing, ID assignment, and randomness
contract ConditioningFunctionDemo {
    uint256 public constant MAX_ID = 10000;
    bytes32 public immutable domainPrefix;

    constructor(string memory systemDomain) {
        domainPrefix = keccak256(abi.encodePacked("DOMAIN::", systemDomain));
    }

    /// ✅ Hash conditioning with domain separation (e.g., proof or signature input)
    function getConditionedHash(address user, uint256 value) external view returns (bytes32) {
        return keccak256(abi.encodePacked(domainPrefix, user, value));
    }

    /// ✅ Range conditioning: user input mapped to safe range ID
    function getConditionedId(bytes32 inputHash) external pure returns (uint256) {
        require(MAX_ID > 0, "Invalid ID space");
        return uint256(inputHash) % MAX_ID;
    }

    /// ✅ Randomness conditioning: generate pseudo-random number with context + block entropy
    function getConditionedRandom(string calldata label) external view returns (uint256) {
        bytes32 seed = keccak256(abi.encodePacked(domainPrefix, label, block.timestamp, msg.sender, block.prevrandao));
        return uint256(seed) % 1000 + 1; // conditioned to range 1–1000
    }

    /// ✅ Bitmask conditioning: extract specific 8-bit slice from input
    function extractByte(bytes32 data, uint8 byteIndex) external pure returns (uint8) {
        require(byteIndex < 32, "Out of bounds");
        return uint8(bytes1(data << (byteIndex * 8)));
    }
}
