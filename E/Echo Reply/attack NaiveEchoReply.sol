// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NaiveEchoReply {
    event Echoed(address indexed sender, string data);

    function echo(string calldata message) external {
        emit Echoed(msg.sender, message);
    }
}
