// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureAccessControl {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized");
        _;
    }

    modifier onlyAccountHolder(address account) {
        require(msg.sender == account, "Access Denied");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Secure: only the account holder can withdraw their funds
    function withdraw(uint256 amount) public onlyAccountHolder(msg.sender) {
        require(balances[msg.sender] >= amount, "Not enough balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // Secure administrative function restricted to owner only
    function emergencyWithdraw(address payable to, uint256 amount) public onlyOwner {
        require(address(this).balance >= amount, "Insufficient contract balance");
        to.transfer(amount);
    }
}
