// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CoreController {
    address public admin;
    mapping(bytes32 => address) public plugins;
    mapping(address => bool) public isRegistered;

    event PluginRegistered(bytes32 indexed name, address plugin);
    event PluginExecuted(bytes32 indexed name, address triggeredBy);
    event AdminChanged(address newAdmin);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Core: Not admin");
        _;
    }

    modifier onlyRegisteredPlugin() {
        require(isRegistered[msg.sender], "Core: Not a registered plugin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerPlugin(bytes32 name, address plugin) external onlyAdmin {
        require(plugin != address(0), "Invalid plugin address");
        plugins[name] = plugin;
        isRegistered[plugin] = true;

        emit PluginRegistered(name, plugin);
    }

    function changeAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Invalid admin");
        admin = newAdmin;
        emit AdminChanged(newAdmin);
    }

    function executeFromPlugin(bytes32 name) external onlyRegisteredPlugin {
        require(plugins[name] == msg.sender, "Mismatch plugin source");
        emit PluginExecuted(name, msg.sender);

        // Plugin-specific logic would go here or in the plugin
    }

    function getPlugin(bytes32 name) external view returns (address) {
        return plugins[name];
    }
}
