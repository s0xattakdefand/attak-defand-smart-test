// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SecurityDivisionRegistry {
    address public admin;

    struct SecurityModule {
        string name;
        address module;
        bool active;
        uint8 riskTier; // 1 = low, 5 = high
        bytes32 auditHash;
    }

    mapping(string => SecurityModule) public modules;
    string[] public moduleNames;

    event ModuleRegistered(string name, address module, uint8 tier, bytes32 auditHash);
    event ModuleRevoked(string name);
    event ModuleTierChanged(string name, uint8 newTier);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerModule(
        string calldata name,
        address module,
        uint8 riskTier,
        bytes32 auditHash
    ) external onlyAdmin {
        require(modules[name].module == address(0), "Already exists");
        modules[name] = SecurityModule(name, module, true, riskTier, auditHash);
        moduleNames.push(name);
        emit ModuleRegistered(name, module, riskTier, auditHash);
    }

    function revokeModule(string calldata name) external onlyAdmin {
        modules[name].active = false;
        emit ModuleRevoked(name);
    }

    function changeTier(string calldata name, uint8 newTier) external onlyAdmin {
        modules[name].riskTier = newTier;
        emit ModuleTierChanged(name, newTier);
    }

    function getModule(string calldata name) external view returns (SecurityModule memory) {
        return modules[name];
    }

    function listModules() external view returns (string[] memory) {
        return moduleNames;
    }
}
