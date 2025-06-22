// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DataLossPreventionAttackDefense - Full Attack and Defense Simulation for Data Loss Prevention (DLP) Mechanisms
/// @author ChatGPT

/// @notice Secure contract implementing Data Loss Prevention
contract SecureDLPStorage {
    address public owner;
    mapping(address => uint256) private userBalances;
    uint256 private totalDeposits;
    uint256 private backupTotalDeposits;
    mapping(address => uint256) private backupUserBalances;
    bool public locked;

    event BackupCreated();
    event RestoredFromBackup();
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier noReentrant() {
        require(!locked, "Reentrancy blocked");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable noReentrant {
        require(msg.value > 0, "No value sent");
        userBalances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 _amount) external noReentrant {
        require(userBalances[msg.sender] >= _amount, "Insufficient balance");
        userBalances[msg.sender] -= _amount;
        totalDeposits -= _amount;
        payable(msg.sender).transfer(_amount);
        emit Withdraw(msg.sender, _amount);
    }

    function createBackup() external onlyOwner {
        backupTotalDeposits = totalDeposits;
        // Copy balances to backup
        for (uint i = 0; i < backupIndex.length; i++) {
            backupUserBalances[backupIndex[i]] = userBalances[backupIndex[i]];
        }
        emit BackupCreated();
    }

    address[] private backupIndex; // Tracking addresses for backup mapping

    function safeDeposit() external payable noReentrant {
        require(msg.value > 0, "No value sent");
        if (userBalances[msg.sender] == 0) {
            backupIndex.push(msg.sender);
        }
        userBalances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function restoreBackup() external onlyOwner {
        totalDeposits = backupTotalDeposits;
        for (uint i = 0; i < backupIndex.length; i++) {
            userBalances[backupIndex[i]] = backupUserBalances[backupIndex[i]];
        }
        emit RestoredFromBackup();
    }

    function getBalance(address user) external view returns (uint256) {
        return userBalances[user];
    }
}

/// @notice Attack contract trying to bypass DLP and reset storage
contract DLPIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryWipeBackup() external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("restoreBackup()")
        );
        // If access control is properly set, this must fail
    }
}
