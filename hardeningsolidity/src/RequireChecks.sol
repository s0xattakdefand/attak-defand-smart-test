// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Require Check Example - Hardened Donation Contract
contract RequireChecks {
    address public owner;
    uint public constant MIN_DONATION = 0.01 ether;
    uint public constant GOAL = 1 ether;
    uint public totalReceived;

    mapping(address => uint) public donations;

    constructor() {
        owner = msg.sender;
    }

    /// @notice Accept donation only if above minimum and goal not yet reached
    function donate() external payable {
        require(msg.value >= MIN_DONATION, "Donation too small");
        require(totalReceived + msg.value <= GOAL, "Goal reached");

        donations[msg.sender] += msg.value;
        totalReceived += msg.value;
    }

    /// @notice Withdraw only after reaching goal, only by owner
    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        require(totalReceived >= GOAL, "Goal not yet met");

        payable(owner).transfer(address(this).balance);
    }
}
