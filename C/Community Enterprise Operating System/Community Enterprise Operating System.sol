// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommunityEnterpriseOS {
    address public admin;

    struct Module {
        string name;
        address implementation;
        string version;
        bool active;
        uint256 registeredAt;
    }

    mapping(string => Module) public modules;
    string[] public moduleList;

    event ModuleRegistered(string name, address implementation, string version);
    event ModuleUpdated(string name, address newImplementation, string newVersion);
    event ModuleDisabled(string name);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerModule(string calldata name, address implementation, string calldata version) external onlyAdmin {
        require(modules[name].registeredAt == 0, "Already exists");

        modules[name] = Module({
            name: name,
            implementation: implementation,
            version: version,
            active: true,
            registeredAt: block.timestamp
        });

        moduleList.push(name);
        emit ModuleRegistered(name, implementation, version);
    }

    function updateModule(string calldata name, address newImpl, string calldata newVersion) external onlyAdmin {
        require(modules[name].active, "Module inactive");
        modules[name].implementation = newImpl;
        modules[name].version = newVersion;
        emit ModuleUpdated(name, newImpl, newVersion);
    }

    function disableModule(string calldata name) external onlyAdmin {
        modules[name].active = false;
        emit ModuleDisabled(name);
    }

    function getModule(string calldata name) external view returns (
        address impl,
        string memory version,
        bool active
    ) {
        Module memory m = modules[name];
        return (m.implementation, m.version, m.active);
    }

    function listModules() external view returns (string[] memory) {
        return moduleList;
    }
}
