// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CommitRevealAntiCorruption {
    mapping(address => bytes32) public commitments;

    function commit(bytes32 hash) external {
        commitments[msg.sender] = hash;
    }

    function reveal(string calldata secret) external view returns (bool) {
        return keccak256(abi.encodePacked(secret)) == commitments[msg.sender];
    }
}
