// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// XMSS-like 32-byte prefix, key, bitmask structure
library XMSS32 {
    struct Prefix32 {
        bytes32 value;
    }

    /// Apply prefix to message (concatenation)
    function applyPrefix(Prefix32 memory prefix, bytes memory message) internal pure returns (bytes memory) {
        return abi.encodePacked(prefix.value, message);
    }

    /// XOR mask application to a 32-byte input
    function applyBitmask(bytes32 input, Prefix32 memory mask) internal pure returns (bytes32) {
        return input ^ mask.value;
    }

    /// Domain-separated hash (keccak256-based)
    function prefixedHash(Prefix32 memory prefix, bytes memory message) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(prefix.value, message));
    }

    /// Generate a Prefix32 from a label
    function fromLabel(string memory label) internal pure returns (Prefix32 memory) {
        return Prefix32(keccak256(abi.encodePacked(label)));
    }
}
