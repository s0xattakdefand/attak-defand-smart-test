// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title LoopbackSelfDestruct - Traps funds with self-looping destruct
contract LoopbackSelfDestruct {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    function triggerLoopback() external {
        require(msg.sender == owner, "Only owner");

        // Sends remaining ether to itself — this is a no-op, but can confuse auditors
        selfdestruct(payable(address(this)));
    }

    receive() external payable {}
}
