// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Actual State Access Enforcement — Web3 Secure Logic
contract ActualStateAwareVault {
    address public admin;
    bool public paused;
    mapping(address => uint256) public balances;
    mapping(address => bool) public roles;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event PausedState(bool state);
    event StateQueried(address indexed by, string field, bytes32 value);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyIfActive() {
        require(!paused, "System paused");
        _;
    }

    modifier onlyIfHasFunds() {
        require(balances[msg.sender] > 0, "No funds");
        _;
    }

    constructor() {
        admin = msg.sender;
        roles[admin] = true;
    }

    function deposit() external payable onlyIfActive {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external onlyIfHasFunds onlyIfActive {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawn(msg.sender, amount);
    }

    function pause(bool state) external onlyAdmin {
        paused = state;
        emit PausedState(state);
    }

    /// Actual state query via event
    function queryActualState() external {
        emit StateQueried(msg.sender, "paused", bytes32(uint256(paused ? 1 : 0)));
        emit StateQueried(msg.sender, "balance", bytes32(balances[msg.sender]));
    }
}
