// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBroadcastRelay {
    event Relay(address indexed sender, string message);

    function broadcast(string calldata message) external {
        emit Relay(msg.sender, message);
    }
}
