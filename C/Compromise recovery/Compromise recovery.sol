// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPausable {
    function pause() external;
    function unpause() external;
}

interface IUpgradable {
    function upgradeTo(address newImpl) external;
}

contract CompromiseRecoveryManager {
    address public recoveryGuardian;
    address public backupAdmin;
    address public vault;
    address public upgradable;

    bool public emergencyTriggered;

    event EmergencyTriggered(address indexed by);
    event AdminReplaced(address indexed oldAdmin, address indexed newAdmin);
    event VaultPaused();
    event LogicUpgraded(address indexed newImpl);

    modifier onlyGuardian() {
        require(msg.sender == recoveryGuardian, "Not guardian");
        _;
    }

    constructor(address _vault, address _upgradable, address _backupAdmin) {
        recoveryGuardian = msg.sender;
        vault = _vault;
        upgradable = _upgradable;
        backupAdmin = _backupAdmin;
    }

    function triggerEmergency() external onlyGuardian {
        require(!emergencyTriggered, "Already triggered");
        emergencyTriggered = true;
        IPausable(vault).pause();
        emit EmergencyTriggered(msg.sender);
        emit VaultPaused();
    }

    function replaceAdmin(address newAdmin) external onlyGuardian {
        address old = backupAdmin;
        backupAdmin = newAdmin;
        emit AdminReplaced(old, newAdmin);
    }

    function upgradeLogic(address newImpl) external onlyGuardian {
        require(emergencyTriggered, "Only during emergency");
        IUpgradable(upgradable).upgradeTo(newImpl);
        emit LogicUpgraded(newImpl);
    }
}
