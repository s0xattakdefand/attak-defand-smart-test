// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * A naive echo function that just logs or returns user data 
 * with no controls. Attackers can spam or embed malicious content.
 */
contract NaiveEchoReply {
    event Echoed(address indexed sender, string data);

    /**
     * @dev Echo back the user input in an event. 
     * Attackers can spam huge strings or spam the logs for a DoS-like effect.
     */
    function echo(string calldata message) external {
        // ❌ No limit on size or calls => can fill up logs or cause high gas usage
        emit Echoed(msg.sender, message);
    }
}
