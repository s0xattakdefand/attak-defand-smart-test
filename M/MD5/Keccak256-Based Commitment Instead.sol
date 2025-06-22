// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract KeccakCommitment {
    mapping(bytes32 => address) public commitments;

    function commit(string calldata input) external {
        bytes32 hash = keccak256(abi.encodePacked(input));
        require(commitments[hash] == address(0), "Already committed");
        commitments[hash] = msg.sender;
    }

    function check(string calldata input) external view returns (bool) {
        return commitments[keccak256(abi.encodePacked(input))] != address(0);
    }
}
