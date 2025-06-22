// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableAccessControl {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable: Anyone can call this!
    function withdraw(address payable to, uint256 amount) public {
        require(balances[to] >= amount, "Not enough balance");
        balances[to] -= amount;
        to.transfer(amount);
    }
}
