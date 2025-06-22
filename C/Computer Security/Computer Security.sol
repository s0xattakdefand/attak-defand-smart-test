// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ComputerSecurityGuard {
    address public owner;
    address public guardian;
    bool public paused;

    mapping(address => bool) public admins;
    uint256 public invariantValue;

    event Paused();
    event Unpaused();
    event AdminAdded(address indexed admin);
    event CriticalAction(address indexed actor);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Not admin");
        _;
    }

    modifier notPaused() {
        require(!paused, "Paused");
        _;
    }

    constructor(address _guardian) {
        owner = msg.sender;
        guardian = _guardian;
    }

    function addAdmin(address _admin) external onlyOwner {
        admins[_admin] = true;
        emit AdminAdded(_admin);
    }

    function pause() external {
        require(msg.sender == owner || msg.sender == guardian, "Unauthorized");
        paused = true;
        emit Paused();
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused();
    }

    function criticalAction(uint256 input) external onlyAdmin notPaused {
        invariantValue += input;
        require(invariantValue < 100000, "Invariant breach");
        emit CriticalAction(msg.sender);
    }
}
