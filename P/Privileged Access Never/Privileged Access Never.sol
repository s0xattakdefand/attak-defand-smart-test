// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PrivilegedAccessNeverAttackDefense - Attack and Defense Simulation for Privileged Access Never (PAN) Smart Contracts in Web3
/// @author ChatGPT

/// @notice Insecure PAN Contract (Claims No Privileges, But Owner Remains!)
contract InsecurePAN {
    address public owner;
    bool public locked;

    event OwnershipRenounced(address indexed formerOwner);
    event CriticalActionExecuted(address indexed by);

    constructor() {
        owner = msg.sender;
    }

    function renounceOwnership() external {
        // 🔥 Only marks a flag, does NOT remove owner!
        locked = true;
        emit OwnershipRenounced(msg.sender);
    }

    function criticalAction() external {
        require(msg.sender == owner, "Not owner");
        emit CriticalActionExecuted(msg.sender);
    }
}

/// @notice Secure PAN Contract (Full Owner Renouncement, No Critical Functions, Immutable After Deployment)
contract SecurePAN {
    bool public initialized;
    bool public immutable deployedImmutable;

    event SystemInitialized(address indexed by);

    constructor() {
        deployedImmutable = true;
    }

    function initializeSystem() external {
        require(!initialized, "Already initialized");
        require(tx.origin == msg.sender, "Proxy interactions forbidden");
        initialized = true;
        emit SystemInitialized(msg.sender);
    }

    /// Critical actions are handled via permissionless consensus — no privileged pathways.
}

/// @notice Attack contract simulating fake renouncement exploit
contract PANIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function attemptCriticalAction() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("criticalAction()")
        );
    }
}
