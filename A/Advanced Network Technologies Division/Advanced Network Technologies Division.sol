// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Advanced Network Technologies Division (ANTD) Registry and Upgrade Manager
contract ANTDManager {
    address public networkGovernor;

    struct Module {
        string kind;            // "relayer", "router", "bridge", "zkCircuit"
        address moduleAddress;
        bool active;
        uint256 registeredAt;
    }

    Module[] public modules;
    mapping(address => uint256) public moduleIndex;

    event ModuleRegistered(address indexed module, string kind);
    event ModuleDeactivated(address indexed module);
    event UpgradeProposed(address indexed oldModule, address indexed newModule, string reason);

    modifier onlyGovernor() {
        require(msg.sender == networkGovernor, "Not authorized");
        _;
    }

    constructor() {
        networkGovernor = msg.sender;
    }

    function registerModule(address module, string calldata kind) external onlyGovernor {
        modules.push(Module(kind, module, true, block.timestamp));
        moduleIndex[module] = modules.length - 1;
        emit ModuleRegistered(module, kind);
    }

    function deactivateModule(address module) external onlyGovernor {
        uint256 idx = moduleIndex[module];
        modules[idx].active = false;
        emit ModuleDeactivated(module);
    }

    function proposeUpgrade(address oldModule, address newModule, string calldata reason) external onlyGovernor {
        emit UpgradeProposed(oldModule, newModule, reason);
    }

    function getModule(uint256 index) external view returns (Module memory) {
        return modules[index];
    }

    function totalModules() external view returns (uint256) {
        return modules.length;
    }
}
