// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PolicyAdministrationPointAttackDefense - Attack and Defense Simulation for PAP (Policy Admin Point) in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Policy Administration (No Access Control on Policy Updates)
contract InsecurePAPolicy {
    mapping(bytes32 => bool) public permissions;

    event PolicyUpdated(bytes32 indexed policy, bool allowed);

    function updatePolicy(bytes32 policy, bool allowed) external {
        // 🔥 Anyone can change policies!
        permissions[policy] = allowed;
        emit PolicyUpdated(policy, allowed);
    }

    function checkPolicy(bytes32 policy) external view returns (bool) {
        return permissions[policy];
    }
}

/// @notice Secure Policy Administration (Role-Based, Transparent, Versioned Policy Updates)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecurePAPolicy is Ownable {
    mapping(bytes32 => bool) private permissions;
    mapping(bytes32 => uint256) private policyVersion;
    uint256 public globalPolicyVersion;

    event PolicyUpdated(bytes32 indexed policy, bool allowed, uint256 version);
    event GlobalVersionIncremented(uint256 newVersion);

    function updatePolicy(bytes32 policy, bool allowed) external onlyOwner {
        permissions[policy] = allowed;
        policyVersion[policy] = ++globalPolicyVersion;
        emit PolicyUpdated(policy, allowed, policyVersion[policy]);
        emit GlobalVersionIncremented(globalPolicyVersion);
    }

    function checkPolicy(bytes32 policy) external view returns (bool allowed, uint256 version) {
        allowed = permissions[policy];
        version = policyVersion[policy];
    }

    function batchUpdatePolicies(bytes32[] calldata policies, bool[] calldata allowedStatuses) external onlyOwner {
        require(policies.length == allowedStatuses.length, "Mismatched array lengths");
        for (uint256 i = 0; i < policies.length; i++) {
            permissions[policies[i]] = allowedStatuses[i];
            policyVersion[policies[i]] = ++globalPolicyVersion;
            emit PolicyUpdated(policies[i], allowedStatuses[i], policyVersion[policies[i]]);
        }
        emit GlobalVersionIncremented(globalPolicyVersion);
    }
}

/// @notice Attack contract simulating unauthorized policy manipulation
contract PAPolicyIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectFakePolicy(bytes32 policy) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("updatePolicy(bytes32,bool)", policy, true)
        );
    }
}
