// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * A contract that allows repeated tries (like a guess or re-entrancy) 
 * with no increasing delay or cost => spammers can brute force quickly.
 */
contract NaiveNoBackoff {
    mapping(address => uint256) public attemptCount;

    event Attempted(address indexed user, uint256 count);

    function doAction() external {
        // ❌ Attack: user can repeatedly call 
        // with no increased wait or cost
        attemptCount[msg.sender]++;
        emit Attempted(msg.sender, attemptCount[msg.sender]);
    }
}
