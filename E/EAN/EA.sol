// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() public payable {
        require(msg.value > 0, "Deposit amount must be greater than 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Vulnerable: External call before state update (reentrancy risk)
    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance to withdraw");

        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "Withdrawal failed");

        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, bal);
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}