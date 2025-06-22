// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Defense Type:
 * Use commit-reveal to avoid revealing the actual value in the mempool. 
 * Commit is done with a hash. Then later reveal in a separate transaction, 
 * preventing front-running or eavesdropping on the first tx data.
 */
contract CommitRevealMempool {
    mapping(address => bytes32) public commits;
    mapping(address => uint256) public finalValue;

    event Committed(address indexed user, bytes32 commitHash);
    event Revealed(address indexed user, uint256 value);

    // Step 1: commit a hashed value (secretValue + salt + address)
    function commitValue(bytes32 hashValue) external {
        commits[msg.sender] = hashValue;
        emit Committed(msg.sender, hashValue);
    }

    // Step 2: reveal actual value + salt
    function revealValue(uint256 secretValue, bytes32 salt) external {
        bytes32 checkHash = keccak256(
            abi.encodePacked(secretValue, salt, msg.sender)
        );
        require(checkHash == commits[msg.sender], "Commit mismatch");
        finalValue[msg.sender] = secretValue;
        emit Revealed(msg.sender, secretValue);
    }
}
