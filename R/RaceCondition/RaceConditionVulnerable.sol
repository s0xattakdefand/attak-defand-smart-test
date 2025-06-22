// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract RaceConditionVulnerable {
    mapping(address => uint256) public balance;

    event Claimed(address indexed user, uint256 amount);

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function claim() external {
        uint256 amount = balance[msg.sender];
        require(amount > 0, "Nothing to claim");

        // 🔥 RACE HERE — balance is not updated yet
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        balance[msg.sender] = 0;
        emit Claimed(msg.sender, amount);
    }
}
