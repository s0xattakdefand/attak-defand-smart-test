// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PoliciesAdministratorAttackDefense - Attack and Defense Simulation for Policies Administrator in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Policies Administrator (No Timelock, No Multi-Sig, Single Point of Failure)
contract InsecurePoliciesAdmin {
    address public admin;
    mapping(string => uint256) public policies;

    event PolicyUpdated(string policyName, uint256 newValue);

    constructor() {
        admin = msg.sender;
    }

    function updatePolicy(string calldata policyName, uint256 newValue) external {
        require(msg.sender == admin, "Not admin");
        policies[policyName] = newValue;
        emit PolicyUpdated(policyName, newValue);
    }
}

/// @notice Secure Policies Administrator with Timelock and Admin Control
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecurePoliciesAdmin is Ownable {
    struct PendingPolicy {
        uint256 newValue;
        uint256 executionTime;
    }

    uint256 public constant TIMELOCK_DELAY = 10 minutes;

    mapping(string => uint256) public policies;
    mapping(string => PendingPolicy) public pendingPolicies;

    event PolicyUpdateProposed(string policyName, uint256 newValue, uint256 executionTime);
    event PolicyUpdated(string policyName, uint256 newValue);

    constructor() {
        _transferOwnership(msg.sender);
    }

    function proposePolicyUpdate(string calldata policyName, uint256 newValue) external onlyOwner {
        uint256 executionTime = block.timestamp + TIMELOCK_DELAY;
        pendingPolicies[policyName] = PendingPolicy(newValue, executionTime);
        emit PolicyUpdateProposed(policyName, newValue, executionTime);
    }

    function executePolicyUpdate(string calldata policyName) external {
        PendingPolicy memory pending = pendingPolicies[policyName];
        require(pending.executionTime > 0, "No pending update");
        require(block.timestamp >= pending.executionTime, "Timelock not expired");

        policies[policyName] = pending.newValue;
        delete pendingPolicies[policyName];

        emit PolicyUpdated(policyName, policies[policyName]);
    }
}

/// @notice Attack contract trying to hijack policy updates
contract PolicyIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackPolicy(string calldata policyName, uint256 newValue) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("updatePolicy(string,uint256)", policyName, newValue)
        );
    }
}
