// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * Anyone can emit large strings in an event 
 * => spam or fill up logs, degrade off-chain indexing, 
 * no checks or cost.
 */
contract NaiveEventSpam {
    event UserMessage(address indexed user, string message);

    /**
     * @dev No rate limit or fee => attacker can repeatedly call 
     * to fill logs with huge data.
     */
    function emitMessage(string calldata msgData) external {
        emit UserMessage(msg.sender, msgData);
    }
}
