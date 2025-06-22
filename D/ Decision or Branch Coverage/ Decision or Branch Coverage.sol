// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DecisionBranchCoverageAttackDefense - Full Attack and Defense Simulation for Decision/Branch Coverage Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Branch Logic (with Incomplete Coverage)
contract InsecureBranchContract {
    address public owner;
    uint256 public balance;

    constructor() {
        owner = msg.sender;
    }

    function riskyWithdraw(uint256 amount) external {
        // Only partly protected
        if (msg.sender == owner) {
            balance -= amount; // Missing check for underflow risk!
        } else if (amount < 10 ether) {
            balance -= amount / 2; // Half withdrawal for others
        } // No fallback else (undefined behavior)

        // No validation if balance went negative
    }

    function deposit() external payable {
        balance += msg.value;
    }
}

/// @notice Secure Branch Logic (Full Coverage Defense)
contract SecureBranchContract {
    address public owner;
    uint256 public balance;
    bool private locked;

    constructor() {
        owner = msg.sender;
    }

    modifier lock() {
        require(!locked, "Reentrancy Guard");
        locked = true;
        _;
        locked = false;
    }

    function safeWithdraw(uint256 amount) external lock {
        require(balance >= amount, "Insufficient balance");

        if (msg.sender == owner) {
            balance -= amount;
            (bool sent, ) = msg.sender.call{value: amount}("");
            require(sent, "Transfer failed");
        } else if (amount <= 10 ether) {
            uint256 withdrawAmount = amount / 2;
            require(balance >= withdrawAmount, "Insufficient for half withdrawal");
            balance -= withdrawAmount;
            (bool sent, ) = msg.sender.call{value: withdrawAmount}("");
            require(sent, "Transfer failed");
        } else {
            revert("Unauthorized or excessive withdrawal");
        }
    }

    function deposit() external payable lock {
        balance += msg.value;
    }

    function getBalance() external view returns (uint256) {
        return balance;
    }
}

/// @notice Attack contract simulating branch bypass attempts
contract BranchCoverageIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function attackWithdraw(uint256 amount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("riskyWithdraw(uint256)", amount)
        );
    }
}
