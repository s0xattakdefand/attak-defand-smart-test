// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NoMonitoring {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
        balances[msg.sender] = 100 ether;
    }

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient funds");
        balances[msg.sender] -= amount;
        balances[to] += amount;

        // ❌ No event or monitoring — invisible to auditors
    }

    function adminWithdraw(uint256 amount) public {
        require(msg.sender == owner, "Not authorized");
        balances[msg.sender] += amount;
        // ❌ No tracking — suspicious withdrawals undetected
    }
}
