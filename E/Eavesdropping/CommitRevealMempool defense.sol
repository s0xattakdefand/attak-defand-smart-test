// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Defense: commit-reveal to hide the value from mempool watchers
 */
contract CommitRevealMempool {
    mapping(address => bytes32) public commits;
    mapping(address => uint256) public finalValue;

    event Committed(address indexed user, bytes32 commitHash);
    event Revealed(address indexed user, uint256 value);

    function commitValue(bytes32 hashValue) external {
        commits[msg.sender] = hashValue;
        emit Committed(msg.sender, hashValue);
    }

    function revealValue(uint256 secretValue, bytes32 salt) external {
        bytes32 check = keccak256(abi.encodePacked(secretValue, salt, msg.sender));
        require(check == commits[msg.sender], "Commit mismatch");
        finalValue[msg.sender] = secretValue;
        emit Revealed(msg.sender, secretValue);
    }
}
