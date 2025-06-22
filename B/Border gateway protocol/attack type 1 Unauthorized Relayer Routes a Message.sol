// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BGPSpoofedRoute {
    event MessageReceived(address relayer, string message);

    function receiveMessage(string memory message) public {
        // ❌ No validation of the relayer or path
        emit MessageReceived(msg.sender, message);
    }
}
