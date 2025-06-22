// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AgileModuleManager — Demonstrates contract agility via module switching
contract AgileModuleManager {
    address public admin;
    address public currentModule;
    string public version;

    event ModuleUpdated(address indexed oldModule, address indexed newModule, string version);
    event EmergencyDeactivated(address indexed module);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor(address initialModule, string memory initialVersion) {
        admin = msg.sender;
        currentModule = initialModule;
        version = initialVersion;
        emit ModuleUpdated(address(0), initialModule, initialVersion);
    }

    function updateModule(address newModule, string calldata newVersion) external onlyAdmin {
        address old = currentModule;
        currentModule = newModule;
        version = newVersion;
        emit ModuleUpdated(old, newModule, newVersion);
    }

    function deactivateModule() external onlyAdmin {
        emit EmergencyDeactivated(currentModule);
        currentModule = address(0);
    }

    function getModule() external view returns (address, string memory) {
        return (currentModule, version);
    }
}
