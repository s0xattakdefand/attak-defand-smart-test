// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CyberAttackSimulator - Demonstrates and protects against basic Web3 cyber attacks

interface IVictim {
    function withdraw(uint256 amount) external;
}

contract CyberAttackSimulator {
    address public owner;
    bool internal locked;

    mapping(address => uint256) public balances;

    event AttackAttempt(address attacker, bool success);
    event DefenseTriggered(string reason);

    modifier reentrancyGuard() {
        require(!locked, "Reentrancy blocked");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    // Deposit funds
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable withdraw (intentionally insecure)
    function unsafeWithdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        (bool success, ) = msg.sender.call{value: amount}(""); // vulnerable
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
        emit AttackAttempt(msg.sender, true); // Simulate detection
    }

    // Secure withdraw with reentrancy protection
    function safeWithdraw() external reentrancyGuard {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit DefenseTriggered("ReentrancyGuard triggered");
    }

    // Attacker contract simulation
    receive() external payable {
        if (address(this).balance > 0.01 ether) {
            emit AttackAttempt(msg.sender, false);
        }
    }
}
