// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Attack: Plain data in mempool
 */
contract NaiveMempoolTX {
    mapping(address => uint256) public userValues;

    event ValueSet(address indexed user, uint256 value);

    function setUserValue(uint256 secretValue) external {
        // This reveals 'secretValue' in the transaction data
        userValues[msg.sender] = secretValue;
        emit ValueSet(msg.sender, secretValue);
    }
}
