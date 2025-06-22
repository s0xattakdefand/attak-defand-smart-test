// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ComputerAbuseDefense {
    address public admin;
    uint256 public constant MIN_INTERVAL = 60; // 1 minute between sensitive actions
    uint256 public constant MAX_GAS_TRACK = 500_000;

    mapping(address => uint256) public lastCall;
    mapping(address => uint256) public gasUsed;
    mapping(address => bool) public blacklisted;

    event AbuseDetected(address user, string reason);
    event CriticalAction(address user);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier abuseCheck() {
        require(!blacklisted[msg.sender], "Abusive address");
        require(block.timestamp > lastCall[msg.sender] + MIN_INTERVAL, "Too frequent");
        _;
        lastCall[msg.sender] = block.timestamp;
        gasUsed[msg.sender] += gasleft();
        if (gasUsed[msg.sender] > MAX_GAS_TRACK) {
            blacklisted[msg.sender] = true;
            emit AbuseDetected(msg.sender, "Excessive gas usage");
        }
    }

    constructor() {
        admin = msg.sender;
    }

    function performCriticalAction() external abuseCheck {
        emit CriticalAction(msg.sender);
        // Logic goes here...
    }

    function removeFromBlacklist(address user) external onlyAdmin {
        blacklisted[user] = false;
        gasUsed[user] = 0;
    }

    function setGasLimit(uint256 newLimit) external onlyAdmin {
        require(newLimit >= 100_000, "Too low");
        // Admin can adjust the gas abuse threshold
    }
}
