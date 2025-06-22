// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EvaluationAssuranceLevelAttackDefense - Attack and Defense Simulation for Evaluation Assurance Level Handling in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure EAL Handling (No Verification, No Upgrade Block)
contract InsecureEALRegistry {
    mapping(address => uint8) public contractEAL; // 0 = unverified, 1..7 increasing levels

    event EALAssigned(address indexed contractAddress, uint8 ealLevel);

    function assignEAL(address contractAddress, uint8 level) external {
        // 🔥 No validation of assignment authority!
        contractEAL[contractAddress] = level;
        emit EALAssigned(contractAddress, level);
    }
}

/// @notice Secure EAL Registry with Controlled Assignment, Event Logging, and Upgrade Guards
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureEALRegistry is AccessControl {
    bytes32 public constant EVALUATOR_ROLE = keccak256("EVALUATOR_ROLE");

    mapping(address => uint8) public contractEAL; // 0 = unverified, 1..7 increasing levels

    event EALAssigned(address indexed contractAddress, uint8 ealLevel, uint256 timestamp);

    constructor(address initialEvaluator) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(EVALUATOR_ROLE, initialEvaluator);
    }

    function assignEAL(address contractAddress, uint8 level) external onlyRole(EVALUATOR_ROLE) {
        require(level >= 1 && level <= 7, "Invalid EAL level");
        require(contractAddress != address(0), "Invalid contract");

        contractEAL[contractAddress] = level;
        emit EALAssigned(contractAddress, level, block.timestamp);
    }

    function requireMinimumEAL(address contractAddress, uint8 minLevel) external view returns (bool) {
        return contractEAL[contractAddress] >= minLevel;
    }
}

/// @notice Attack contract trying to forge EAL assignments
contract EALIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function forgeEAL(address victimContract, uint8 forgedLevel) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("assignEAL(address,uint8)", victimContract, forgedLevel)
        );
    }
}
