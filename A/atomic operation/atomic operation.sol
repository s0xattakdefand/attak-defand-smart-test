// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AtomicBatchExecutor - Ensures multiple actions complete atomically

contract AtomicBatchExecutor {
    address public admin;
    mapping(address => uint256) public balances;

    event ActionExecuted(address indexed user, uint256 amount);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function atomicBatchTransfer(
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external {
        require(recipients.length == amounts.length, "Mismatched arrays");

        uint256 total = 0;
        for (uint i = 0; i < amounts.length; i++) {
            total += amounts[i];
        }

        require(balances[msg.sender] >= total, "Insufficient balance");

        // Apply all or revert all
        for (uint i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amounts[i];
            emit ActionExecuted(recipients[i], amounts[i]);
        }

        balances[msg.sender] -= total;
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
