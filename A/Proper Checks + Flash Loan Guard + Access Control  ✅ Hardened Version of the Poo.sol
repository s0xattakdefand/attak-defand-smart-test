// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecurePool {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyExternallyOwnedAccounts() {
        require(msg.sender == tx.origin, "No contracts allowed");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable onlyExternallyOwnedAccounts {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public onlyExternallyOwnedAccounts {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    function receiveLoan(uint256) public pure {
        revert("Flash loans not accepted");
    }
}
