// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DoubleSpendVulnerable {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    // Deposit ETH to increase balance
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Vulnerable withdrawal function: Checks balance but updates it AFTER external call
    // This allows reentrancy: Attacker can call withdraw again before balance is reduced
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // DANGEROUS: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        // State update AFTER call: Vulnerable to double spend
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    // Get balance of an address
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }
}