// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Other Type D: Double-hash or alternate hashing approach
 * to reduce collision concerns or match external protocols.
 */
contract DoubleHash {
    /**
     * @dev Double-hash: keccak256( keccak256(data) ).
     * Overkill for typical usage, but used in certain bridging or legacy designs.
     */
    function doubleHash(bytes memory data) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(data)));
    }

    /**
     * @dev Example of an alternative hashing approach that you might need
     * to match another chain's standard. Here, we do an extra keccak256 for demonstration.
     */
    function altDoubleHash(bytes memory data) public pure returns (bytes32) {
        bytes32 tempHash = keccak256(abi.encodePacked(data));
        return keccak256(abi.encodePacked(tempHash));
    }
}
