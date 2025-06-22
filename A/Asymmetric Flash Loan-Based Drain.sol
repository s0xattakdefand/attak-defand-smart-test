// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFlashLoanProvider {
    function flashLoan(uint256 amount) external;
}

contract VulnerablePool {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    // Called during flashLoan execution
    function receiveLoan(uint256 amount) public {
        // Vulnerability: Updates balance without checks
        balances[msg.sender] += amount;
    }
}
