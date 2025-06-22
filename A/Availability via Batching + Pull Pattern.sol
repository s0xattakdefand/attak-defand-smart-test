// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AvailableAndSecure {
    mapping(address => uint256) public rewards;
    address[] public users;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function register() public {
        users.push(msg.sender);
    }

    // Admin can batch-assign rewards without sending funds yet
    function assignReward(address user, uint256 amount) public {
        require(msg.sender == admin, "Not authorized");
        rewards[user] += amount;
    }

    // Pull pattern: each user withdraws independently (availability stays intact)
    function claimReward() public {
        uint256 amount = rewards[msg.sender];
        require(amount > 0, "No reward");
        rewards[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
