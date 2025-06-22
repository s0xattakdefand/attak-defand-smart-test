// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DynamicSubsystemAttackDefense - Full Attack and Defense Simulation for Dynamic Subsystem Architecture in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Secure Dynamic Subsystem Manager Contract
contract SecureDynamicSubsystemManager {
    address public owner;
    address public multisig;
    uint256 public upgradeDelay = 2 days;
    uint256 public subsystemCounter;
    bool private locked;

    struct Subsystem {
        address implementation;
        uint256 registeredAt;
        uint256 readyToUpgradeAt;
        bool active;
    }

    mapping(uint256 => Subsystem) public subsystems;
    mapping(address => bool) public allowedImplementations;

    event SubsystemRegistered(uint256 indexed id, address implementation, uint256 readyAt);
    event SubsystemActivated(uint256 indexed id);
    event SubsystemDeactivated(uint256 indexed id);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyMultisig() {
        require(msg.sender == multisig, "Only multisig");
        _;
    }

    modifier lock() {
        require(!locked, "Reentrancy Guard");
        locked = true;
        _;
        locked = false;
    }

    constructor(address _multisig) {
        owner = msg.sender;
        multisig = _multisig;
    }

    function proposeSubsystem(address implementation) external onlyOwner returns (uint256) {
        require(implementation != address(0), "Invalid address");

        subsystemCounter++;
        subsystems[subsystemCounter] = Subsystem({
            implementation: implementation,
            registeredAt: block.timestamp,
            readyToUpgradeAt: block.timestamp + upgradeDelay,
            active: false
        });

        emit SubsystemRegistered(subsystemCounter, implementation, block.timestamp + upgradeDelay);
        return subsystemCounter;
    }

    function activateSubsystem(uint256 id) external onlyMultisig lock {
        Subsystem storage sub = subsystems[id];
        require(!sub.active, "Already active");
        require(block.timestamp >= sub.readyToUpgradeAt, "Upgrade delay not passed");

        allowedImplementations[sub.implementation] = true;
        sub.active = true;

        emit SubsystemActivated(id);
    }

    function deactivateSubsystem(uint256 id) external onlyMultisig lock {
        Subsystem storage sub = subsystems[id];
        require(sub.active, "Already inactive");

        allowedImplementations[sub.implementation] = false;
        sub.active = false;

        emit SubsystemDeactivated(id);
    }

    function isAllowed(address implementation) external view returns (bool) {
        return allowedImplementations[implementation];
    }
}

/// @notice Attack contract trying to inject a fake dynamic subsystem
contract DynamicSubsystemIntruder {
    address public targetManager;

    constructor(address _targetManager) {
        targetManager = _targetManager;
    }

    function tryFakeRegister(address fakeSubsystem) external returns (bool success) {
        (success, ) = targetManager.call(
            abi.encodeWithSignature("proposeSubsystem(address)", fakeSubsystem)
        );
    }
}
