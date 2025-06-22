// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another pattern: commit a hashed message first, reveal later => 
 * no mempool eavesdropping of the actual content.
 */
contract EchoCommitReveal {
    mapping(address => bytes32) public commits;
    mapping(address => string) public finalMessage;

    event Committed(address user, bytes32 commitHash);
    event Revealed(address user, string message);

    function commitHash(bytes32 hashValue) external {
        commits[msg.sender] = hashValue;
        emit Committed(msg.sender, hashValue);
    }

    function reveal(string calldata message, bytes32 salt) external {
        bytes32 check = keccak256(abi.encodePacked(message, salt, msg.sender));
        require(check == commits[msg.sender], "Commit mismatch");
        finalMessage[msg.sender] = message;
        emit Revealed(msg.sender, message);
    }
}
