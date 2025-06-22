// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MeasureTimeToRecoveryAttackDefense - Full Attack and Defense Simulation for MTTR in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure System (No Emergency Pause, No Recovery)
contract InsecureMTTR {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdraw failed");
    }
}

/// @notice Secure System (Emergency Pause, Incident Logging, Recovery Measurement)
contract SecureMTTR {
    address public immutable owner;
    bool public paused;
    uint256 public lastIncidentTimestamp;
    uint256 public lastRecoveryTimestamp;

    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event EmergencyPaused(address indexed by, uint256 timestamp);
    event EmergencyResumed(address indexed by, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable whenNotPaused {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external whenNotPaused {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdraw failed");
    }

    function emergencyPause() external onlyOwner {
        paused = true;
        lastIncidentTimestamp = block.timestamp;
        emit EmergencyPaused(msg.sender, block.timestamp);
    }

    function emergencyResume() external onlyOwner {
        require(paused, "Not paused");
        paused = false;
        lastRecoveryTimestamp = block.timestamp;
        emit EmergencyResumed(msg.sender, block.timestamp);
    }

    function measureTimeToRecovery() external view returns (uint256) {
        require(lastIncidentTimestamp > 0 && lastRecoveryTimestamp > 0, "No full cycle yet");
        require(lastRecoveryTimestamp > lastIncidentTimestamp, "Recovery not completed");
        return lastRecoveryTimestamp - lastIncidentTimestamp;
    }
}

/// @notice Attack contract simulating system spam without pause protection
contract MTTRIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function spamDeposit() external payable returns (bool success) {
        (success, ) = targetInsecure.call{value: msg.value}(
            abi.encodeWithSignature("deposit()")
        );
    }
}
