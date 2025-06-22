// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract CommitReveal {
    mapping(address => bytes32) public commitments;

    event Committed(address indexed user, bytes32 hash);
    event Revealed(address indexed user, string data);

    function commit(bytes32 hash) external {
        commitments[msg.sender] = hash;
        emit Committed(msg.sender, hash);
    }

    function reveal(string calldata secret) external {
        require(commitments[msg.sender] == keccak256(abi.encodePacked(secret)), "Invalid reveal");
        emit Revealed(msg.sender, secret);
        delete commitments[msg.sender];
    }
}
