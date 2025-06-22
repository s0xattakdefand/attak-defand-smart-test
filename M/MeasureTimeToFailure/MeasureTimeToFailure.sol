// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MeasureTimeToFailureAttackDefense - Full Attack and Defense Simulation for MTTF in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure System (No Failure Detection, No MTTF Monitoring)
contract InsecureMTTF {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit"); // Basic validation
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function riskyWithdraw(uint256 amount) external {
        balances[msg.sender] -= amount; // BAD: No balance check, possible underflow
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdraw failed");
    }
}

/// @notice Secure System (Failure Detection + Time to Failure Measurement + Safe Modes)
contract SecureMTTF {
    address public immutable owner;
    bool public safeMode;
    uint256 public deploymentTimestamp;
    uint256 public firstFailureTimestamp;
    bool public failureDetected;

    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event FailureDetected(address indexed by, string reason, uint256 failureTime);
    event SafeModeActivated(address indexed by, uint256 time);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier checkSafeMode() {
        require(!safeMode, "Contract in Safe Mode");
        _;
    }

    constructor() {
        owner = msg.sender;
        deploymentTimestamp = block.timestamp;
    }

    function deposit() external payable checkSafeMode {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external checkSafeMode {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) {
            _recordFailure("Withdraw transfer failed");
        }
    }

    function _recordFailure(string memory reason) internal {
        if (!failureDetected) {
            failureDetected = true;
            firstFailureTimestamp = block.timestamp;
            safeMode = true;
            emit FailureDetected(msg.sender, reason, block.timestamp);
            emit SafeModeActivated(msg.sender, block.timestamp);
        }
    }

    function measureTimeToFailure() external view returns (uint256) {
        require(failureDetected, "No failure recorded yet");
        return firstFailureTimestamp - deploymentTimestamp;
    }

    function activateSafeMode() external onlyOwner {
        safeMode = true;
        emit SafeModeActivated(msg.sender, block.timestamp);
    }
}

/// @notice Attack contract simulating failure flooding
contract MTTFIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function forceFailure(uint256 withdrawAmount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("riskyWithdraw(uint256)", withdrawAmount)
        );
    }
}
