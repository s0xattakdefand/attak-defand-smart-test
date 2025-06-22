// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Attack Type:
 * This contract does a naive pending transaction approach 
 * that can be eavesdropped in the mempool => attacker front-runs 
 * user actions or sees secrets from the transaction data.
 */
contract NaiveMempoolTX {
    mapping(address => uint256) public userValues;
    event ValueSet(address indexed user, uint256 value);

    function setUserValue(uint256 secretValue) external {
        // ❌ Attack: The transaction data reveals 'secretValue' 
        // before it's mined, attacker can front-run or replicate
        userValues[msg.sender] = secretValue;
        emit ValueSet(msg.sender, secretValue);
    }
}
