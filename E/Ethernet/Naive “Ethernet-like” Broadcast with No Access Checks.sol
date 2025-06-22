// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * A naive local broadcast function that sends data to all “connected addresses” 
 * with no membership or security. Attackers can join or spam the broadcast domain.
 */
contract NaiveLANBroadcast {
    address[] public participants;
    event Broadcast(address indexed from, bytes message);

    constructor(address[] memory initialMembers) {
        // naive: any addresses are considered “on the same LAN”
        for (uint256 i = 0; i < initialMembers.length; i++) {
            participants.push(initialMembers[i]);
        }
    }

    /**
     * @dev Anyone calls broadcast, spamming data to all participants 
     * => no checks, no membership gating => potential DOS or spam
     */
    function broadcastMessage(bytes calldata message) external {
        // ❌ Attack: no limit, no fee => broadcast domain can be spammed
        emit Broadcast(msg.sender, message);
    }
}
