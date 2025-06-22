// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// APTTracker — Detect and Mitigate Advanced Persistent Threats
contract APTTracker {
    address public admin;
    bool public paused;

    struct APTLog {
        address actor;
        bytes4 selector;
        uint256 entropyScore;
        uint256 timestamp;
    }

    APTLog[] public logs;
    mapping(address => uint256) public threatScore;
    mapping(address => bool) public flaggedAPT;

    event APTActivityDetected(address indexed actor, bytes4 selector, uint256 score);
    event APTFlagged(address indexed actor);
    event ContractPaused();

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier notPaused() {
        require(!paused, "System paused due to APT threat");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function reportAPT(bytes calldata payload) external notPaused {
        bytes4 selector;
        assembly {
            selector := calldataload(payload.offset)
        }

        uint256 score = entropy(payload);
        logs.push(APTLog(msg.sender, selector, score, block.timestamp));
        threatScore[msg.sender] += score;

        emit APTActivityDetected(msg.sender, selector, score);

        if (threatScore[msg.sender] > 120 && !flaggedAPT[msg.sender]) {
            flaggedAPT[msg.sender] = true;
            emit APTFlagged(msg.sender);
            paused = true;
            emit ContractPaused();
        }
    }

    function entropy(bytes memory input) public pure returns (uint256 score) {
        bytes32 h = keccak256(input);
        for (uint256 i = 0; i < 32; i++) {
            if (uint8(h[i]) % 2 == 1) score++;
        }
    }

    function resetSystem() external onlyAdmin {
        paused = false;
    }

    function isFlagged(address actor) external view returns (bool) {
        return flaggedAPT[actor];
    }

    function getAPTLog(uint256 index) external view returns (APTLog memory) {
        return logs[index];
    }
}
