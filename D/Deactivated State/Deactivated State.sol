// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DeactivatedStateAttackDefense - Full Attack and Defense Simulation for Deactivated State Systems in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Secure Contract Handling Deactivation Properly
contract SecureDeactivatedSystem {
    address public owner;
    bool public isActive;
    bool private locked;

    event Deactivated();
    event Reactivated();

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyActive() {
        require(isActive, "System deactivated");
        _;
    }

    modifier lock() {
        require(!locked, "Reentrancy Guard");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
        isActive = true;
    }

    function deactivate() external onlyOwner lock {
        require(isActive, "Already deactivated");
        isActive = false;
        emit Deactivated();
    }

    function reactivate() external onlyOwner lock {
        require(!isActive, "Already active");
        isActive = true;
        emit Reactivated();
    }

    function criticalOperation(uint256 value) external onlyActive lock {
        // Perform critical logic safely
        require(value > 0, "Invalid input");
        // Business logic continues...
    }

    fallback() external payable {
        require(isActive, "System deactivated (fallback blocked)");
        revert("Direct fallback not allowed");
    }

    receive() external payable {
        require(isActive, "System deactivated (receive blocked)");
    }
}

/// @notice Attack contract trying to bypass deactivation
contract DeactivatedStateIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryForceCriticalOperation(uint256 value) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("criticalOperation(uint256)", value)
        );
    }

    function tryFallbackAttack() external returns (bool success) {
        (success, ) = target.call{value: 0}("");
    }
}
