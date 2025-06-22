// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPlugin {
    function execute(bytes calldata data) external returns (bytes memory);
}

contract ComposedPlatformCore {
    address public admin;
    mapping(bytes32 => address) public modules;
    mapping(bytes32 => bool) public activeModules;

    event ModuleRegistered(bytes32 indexed id, address module);
    event ModuleActivated(bytes32 indexed id);
    event ModuleDeactivated(bytes32 indexed id);
    event PluginExecuted(bytes32 indexed moduleId, bytes data);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerModule(bytes32 id, address module) external onlyAdmin {
        modules[id] = module;
        activeModules[id] = true;
        emit ModuleRegistered(id, module);
    }

    function toggleModule(bytes32 id, bool state) external onlyAdmin {
        activeModules[id] = state;
        if (state) emit ModuleActivated(id);
        else emit ModuleDeactivated(id);
    }

    function callModule(bytes32 id, bytes calldata data) external returns (bytes memory) {
        require(activeModules[id], "Inactive module");
        address mod = modules[id];
        emit PluginExecuted(id, data);
        return IPlugin(mod).execute(data);
    }
}
