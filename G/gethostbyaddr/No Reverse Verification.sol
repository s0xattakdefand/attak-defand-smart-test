// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BlindLogger {
    event Action(address indexed sender, string note);

    function act(string calldata note) external {
        // No reverse check → can't verify who is who
        emit Action(msg.sender, note);
    }
}
