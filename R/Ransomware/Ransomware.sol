// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Ransomware {
    address public owner;
    bool public locked = true;
    uint256 public ransomAmount;
    address public targetVault;
    uint256 public deadline;

    event Locked(address vault);
    event Unlocked(address by);
    event RansomPaid(address victim, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier isLocked() {
        require(locked, "Already unlocked");
        _;
    }

    constructor(address _targetVault, uint256 _ransom, uint256 _duration) {
        owner = msg.sender;
        ransomAmount = _ransom;
        targetVault = _targetVault;
        deadline = block.timestamp + _duration;
        emit Locked(targetVault);
    }

    function payRansom() external payable isLocked {
        require(block.timestamp <= deadline, "Deadline passed");
        require(msg.value >= ransomAmount, "Insufficient ransom");
        locked = false;
        emit RansomPaid(msg.sender, msg.value);
        emit Unlocked(msg.sender);
    }

    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    function detonate() external {
        require(block.timestamp > deadline && locked, "Not expired or not locked");
        selfdestruct(payable(owner)); // 💣 malicious destruction
    }
}
