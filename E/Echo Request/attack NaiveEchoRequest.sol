// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NaiveEchoRequest {
    event EchoRequestReceived(address indexed sender, string data);

    function echoRequest(string calldata message) external {
        emit EchoRequestReceived(msg.sender, message);
    }
}
