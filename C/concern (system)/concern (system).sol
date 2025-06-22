// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConcernManager — Demonstrates clear separation of system concerns in a modular smart contract

contract ConcernManager {
    address public owner;
    uint256 public vaultBalance;
    bool public paused;
    string public systemState;

    address public oracle;
    uint256 public lastOracleValue;

    mapping(address => bool) public authorizedUsers;

    event FundsDeposited(address indexed from, uint256 amount);
    event FundsWithdrawn(address indexed to, uint256 amount);
    event OracleUpdated(uint256 value);
    event StateChanged(string newState);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAuthorized() {
        require(authorizedUsers[msg.sender], "Not authorized");
        _;
    }

    modifier notPaused() {
        require(!paused, "System paused");
        _;
    }

    constructor(address _oracle) {
        owner = msg.sender;
        oracle = _oracle;
        authorizedUsers[owner] = true;
    }

    // 🔐 Access Control Concern
    function grantAccess(address user) external onlyOwner {
        authorizedUsers[user] = true;
    }

    function pauseSystem() external onlyOwner {
        paused = true;
    }

    function unpauseSystem() external onlyOwner {
        paused = false;
    }

    // 💰 Financial Concern
    function depositFunds() external payable notPaused {
        vaultBalance += msg.value;
        emit FundsDeposited(msg.sender, msg.value);
    }

    function withdrawFunds(address payable to, uint256 amount) external onlyAuthorized notPaused {
        require(vaultBalance >= amount, "Insufficient funds");
        vaultBalance -= amount;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "Transfer failed");
        emit FundsWithdrawn(to, amount);
    }

    // 🌐 External Interaction Concern
    function updateFromOracle(uint256 newValue) external {
        require(msg.sender == oracle, "Not oracle");
        lastOracleValue = newValue;
        emit OracleUpdated(newValue);
    }

    // 📦 State Concern
    function setState(string calldata newState) external onlyAuthorized notPaused {
        systemState = newState;
        emit StateChanged(newState);
    }
}
