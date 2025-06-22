// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FailoverAttackDefense - Full Attack and Defense Simulation for Failover Mechanisms in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Failover Contract (Vulnerable to Fake or Multiple Failovers)
contract InsecureFailoverManager {
    address public primary;
    address public backup;

    constructor(address _primary, address _backup) {
        primary = _primary;
        backup = _backup;
    }

    function triggerFailover() external {
        primary = backup; // No verification of failure, no access control!
    }

    function criticalFunction() external view returns (string memory) {
        require(msg.sender == primary, "Only primary can execute");
        return "Primary operation executed.";
    }
}

/// @notice Secure Failover Contract (Full Hardened Failover with Verification and Control)
contract SecureFailoverManager {
    address public primary;
    address public backup;
    bool public failedOver;
    uint256 public lastHeartbeat;
    uint256 public heartbeatTimeout = 10 minutes;

    event HeartbeatReceived(address indexed from, uint256 timestamp);
    event FailoverTriggered(address indexed newPrimary);

    modifier onlyPrimary() {
        require(msg.sender == primary, "Only primary allowed");
        _;
    }

    modifier onlyBackup() {
        require(msg.sender == backup, "Only backup allowed");
        _;
    }

    constructor(address _primary, address _backup) {
        require(_primary != _backup, "Primary and backup must differ");
        primary = _primary;
        backup = _backup;
        lastHeartbeat = block.timestamp;
    }

    function heartbeat() external onlyPrimary {
        lastHeartbeat = block.timestamp;
        emit HeartbeatReceived(msg.sender, block.timestamp);
    }

    function triggerFailover() external onlyBackup {
        require(!failedOver, "Already failed over");
        require(block.timestamp > lastHeartbeat + heartbeatTimeout, "Primary still healthy");

        primary = backup;
        failedOver = true;

        emit FailoverTriggered(primary);
    }

    function criticalFunction() external view returns (string memory) {
        require(msg.sender == primary, "Only primary allowed");
        return "Primary operation executed.";
    }
}

/// @notice Attack contract trying to force unauthorized failover
contract FailoverIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackFailover() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("triggerFailover()")
        );
    }
}
