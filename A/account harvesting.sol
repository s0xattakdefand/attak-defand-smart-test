// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableAccountHarvesting {
    address[] public userAccounts;
    mapping(address => uint256) public balances;

    function registerUser() public {
        userAccounts.push(msg.sender);
        balances[msg.sender] = 1 ether;
    }

    // Vulnerable: Anyone can enumerate all accounts
    function getAllUsers() public view returns (address[] memory) {
        return userAccounts;
    }
}
