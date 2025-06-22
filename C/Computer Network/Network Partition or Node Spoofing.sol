// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Attack scenario: A naive contract references a 'network node' 
 * address that might be spoofed or parted from the main net. 
 * If an attacker sets themselves as the node, they can feed false data 
 * or block certain txs from being known by the contract.
 */
contract NaiveNetworkNode {
    address public nodeAddress;  // set by admin
    uint256 public readValue;

    constructor(address node) {
        nodeAddress = node;
    }

    function updateData(uint256 newVal) external {
        // ❌ Only 'nodeAddress' can call, but if that node is compromised 
        //    or if the contract is parted from real mainnet,
        //    the attacker can feed false data or block real updates.
        require(msg.sender == nodeAddress, "Not the node");
        readValue = newVal;
    }
}
