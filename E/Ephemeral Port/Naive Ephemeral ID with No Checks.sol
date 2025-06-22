// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * A naive ephemeral session that acts like an ephemeral port number for a short-living “channel”.
 * No checks => collisions or hijacking possible.
 */
contract NaiveEphemeralSession {
    // sessionID => user
    mapping(uint256 => address) public sessionOwner;

    event SessionCreated(uint256 indexed sessionID, address owner);

    /**
     * @dev Any user picks a sessionID. 
     * Attack: an attacker can guess or re-use it => collisions or hijack
     */
    function createSession(uint256 sessionID) external {
        // ❌ No check if sessionID in use or random
        sessionOwner[sessionID] = msg.sender;
        emit SessionCreated(sessionID, msg.sender);
    }
}
