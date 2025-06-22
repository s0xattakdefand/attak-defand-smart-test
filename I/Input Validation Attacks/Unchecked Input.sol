// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UncheckedTransfer {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount; // ❌ underflow
        balances[to] += amount;
    }
}
