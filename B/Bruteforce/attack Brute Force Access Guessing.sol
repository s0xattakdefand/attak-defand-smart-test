// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BruteForceVulnerable {
    bytes32 public secretHash;

    constructor(string memory _secret) {
        secretHash = keccak256(abi.encodePacked(_secret));
    }

    function guess(string memory guessWord) public view returns (bool) {
        return keccak256(abi.encodePacked(guessWord)) == secretHash;
    }
}
