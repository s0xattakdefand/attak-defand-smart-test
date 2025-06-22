// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * A naive ACL that checks only one simple condition (like 'owner == msg.sender') 
 * or no condition. Attackers can exploit the lack of extended checks for more complex logic.
 */
contract NaiveACL {
    address public owner;
    uint256 public importantData;

    constructor() {
        owner = msg.sender;
    }

    function setData(uint256 newData) external {
        // ❌ Attack: We only check a single condition or none
        // Suppose we forgot to do `require(msg.sender == owner, "Not owner");`
        // => anyone can set data
        importantData = newData;
    }
}
