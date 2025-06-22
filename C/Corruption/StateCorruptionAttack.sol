// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StateCorruptionAttack {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function corrupt(address target) external {
        balances[target] += 1e18; // ❌ Unauthorized mutation
    }
}
