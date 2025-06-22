// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ControlAssessmentTarget — Simulates a contract with assessable control features
contract ControlAssessmentTarget {
    address public owner;
    bool public paused;
    mapping(address => bool) public admins;
    mapping(address => bool) public operators;

    event OwnerTransferred(address oldOwner, address newOwner);
    event AdminGranted(address indexed user);
    event OperatorGranted(address indexed user);
    event PausedStateChanged(bool paused);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Not admin");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender], "Not operator");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // 🔐 Access Control Points

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnerTransferred(owner, newOwner);
        owner = newOwner;
    }

    function grantAdmin(address user) external onlyOwner {
        admins[user] = true;
        emit AdminGranted(user);
    }

    function grantOperator(address user) external onlyAdmin {
        operators[user] = true;
        emit OperatorGranted(user);
    }

    function togglePause(bool _paused) external onlyAdmin {
        paused = _paused;
        emit PausedStateChanged(_paused);
    }

    // ✅ Assessable Logic Function
    function performSensitiveAction() external onlyOperator whenNotPaused returns (string memory) {
        return "Sensitive action executed securely.";
    }
}
