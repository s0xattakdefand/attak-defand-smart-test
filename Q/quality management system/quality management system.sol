// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title QualityManagementSystemAttackDefense - Attack and Defense Simulation for Quality Management System in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure QMS Handling (No threshold enforcement, No audit trail)
contract InsecureQMS {
    uint256 public operationalThreshold;

    event ThresholdUpdated(uint256 newThreshold);

    constructor(uint256 _initialThreshold) {
        operationalThreshold = _initialThreshold;
    }

    function updateThreshold(uint256 newThreshold) external {
        // 🔥 No validation or process control!
        operationalThreshold = newThreshold;
        emit ThresholdUpdated(newThreshold);
    }
}

/// @notice Secure QMS Handling with Strict Thresholds, Audit Trails, and Validation
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureQMS is Ownable {
    uint256 public operationalThreshold;
    uint256 public constant MIN_THRESHOLD = 50;
    uint256 public constant MAX_THRESHOLD = 1000;

    struct AuditRecord {
        uint256 previousThreshold;
        uint256 newThreshold;
        uint256 timestamp;
    }

    AuditRecord[] public auditTrail;

    event ThresholdChangeRequested(address indexed admin, uint256 newThreshold, uint256 timestamp);
    event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold, uint256 timestamp);

    constructor(uint256 _initialThreshold) {
        require(_initialThreshold >= MIN_THRESHOLD && _initialThreshold <= MAX_THRESHOLD, "Initial threshold out of bounds");
        operationalThreshold = _initialThreshold;
    }

    function proposeThresholdChange(uint256 newThreshold) external onlyOwner {
        require(newThreshold >= MIN_THRESHOLD && newThreshold <= MAX_THRESHOLD, "New threshold out of bounds");

        emit ThresholdChangeRequested(msg.sender, newThreshold, block.timestamp);
    }

    function executeThresholdChange(uint256 newThreshold) external onlyOwner {
        require(newThreshold >= MIN_THRESHOLD && newThreshold <= MAX_THRESHOLD, "New threshold out of bounds");

        AuditRecord memory record = AuditRecord({
            previousThreshold: operationalThreshold,
            newThreshold: newThreshold,
            timestamp: block.timestamp
        });

        auditTrail.push(record);
        operationalThreshold = newThreshold;

        emit ThresholdUpdated(record.previousThreshold, record.newThreshold, record.timestamp);
    }

    function getAuditTrailLength() external view returns (uint256) {
        return auditTrail.length;
    }

    function getAuditRecord(uint256 index) external view returns (AuditRecord memory) {
        require(index < auditTrail.length, "Invalid audit record index");
        return auditTrail[index];
    }
}

/// @notice Attack contract trying to bypass quality controls
contract QMSIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function bypassThresholdControl(uint256 dangerousThreshold) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("updateThreshold(uint256)", dangerousThreshold)
        );
    }
}
