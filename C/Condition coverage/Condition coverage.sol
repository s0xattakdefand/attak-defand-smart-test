// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConditionVault — Demonstrates complex conditions with testable logic
contract ConditionVault {
    address public owner;
    bool public paused;
    mapping(address => bool) public whitelisted;
    uint256 public minDeposit;

    constructor(uint256 _minDeposit) {
        owner = msg.sender;
        minDeposit = _minDeposit;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier notPaused() {
        require(!paused, "Paused");
        _;
    }

    function setPaused(bool status) external onlyOwner {
        paused = status;
    }

    function setWhitelist(address user, bool allowed) external onlyOwner {
        whitelisted[user] = allowed;
    }

    function deposit() external payable notPaused {
        require(whitelisted[msg.sender], "Not whitelisted");
        require(msg.value >= minDeposit, "Below minimum");
    }
}
