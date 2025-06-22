// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GenericAttackDefense - Full Attack and Defense Simulation for Generic Mechanisms in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Generic Handler (Overly Broad and Unrestricted)
contract InsecureGeneric {
    event GenericAction(address indexed caller, string action, bytes data);

    function performGenericAction(string calldata action, bytes calldata data) external {
        // BAD: Any caller can trigger any generic action without validation
        emit GenericAction(msg.sender, action, data);
    }
}

/// @notice Secure Generic Handler (Context-Validated, Restricted Generic Execution)
contract SecureGeneric {
    address public immutable owner;
    mapping(string => bool) public approvedActions;

    event SecureGenericAction(address indexed caller, string action, bytes data);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor(string[] memory allowedActions) {
        owner = msg.sender;
        for (uint256 i = 0; i < allowedActions.length; i++) {
            approvedActions[allowedActions[i]] = true;
        }
    }

    function performGenericAction(string calldata action, bytes calldata data) external {
        require(approvedActions[action], "Action not allowed");
        require(msg.sender == owner, "Unauthorized generic action");

        emit SecureGenericAction(msg.sender, action, data);
    }

    function addApprovedAction(string calldata action) external onlyOwner {
        approvedActions[action] = true;
    }

    function removeApprovedAction(string calldata action) external onlyOwner {
        approvedActions[action] = false;
    }
}

/// @notice Attack contract simulating abuse of generic logic
contract GenericIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function abuseGeneric(string calldata maliciousAction, bytes calldata maliciousData) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("performGenericAction(string,bytes)", maliciousAction, maliciousData)
        );
    }
}
