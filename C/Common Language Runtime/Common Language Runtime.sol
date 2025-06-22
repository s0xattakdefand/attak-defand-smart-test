// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CLREngine {
    address public admin;

    struct Module {
        address implementation;
        string language;       // e.g., "Solidity", "Vyper", "Yul"
        bytes4 interfaceId;
        bool active;
    }

    mapping(bytes32 => Module) public modules;

    event ModuleRegistered(bytes32 indexed moduleId, address implementation, string language);
    event ModuleExecuted(bytes32 indexed moduleId, address indexed caller, bool success, bytes result);

    modifier onlyAdmin() {
        require(msg.sender == admin, "CLR: Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerModule(
        bytes32 moduleId,
        address implementation,
        string calldata language,
        bytes4 interfaceId
    ) external onlyAdmin {
        modules[moduleId] = Module(implementation, language, interfaceId, true);
        emit ModuleRegistered(moduleId, implementation, language);
    }

    function executeModule(bytes32 moduleId, bytes calldata data) external returns (bool success, bytes memory result) {
        Module memory m = modules[moduleId];
        require(m.active, "CLR: Module not active");

        (success, result) = m.implementation.call(data);
        emit ModuleExecuted(moduleId, msg.sender, success, result);
    }

    function getModule(bytes32 moduleId) external view returns (
        address implementation,
        string memory language,
        bytes4 interfaceId,
        bool active
    ) {
        Module memory m = modules[moduleId];
        return (m.implementation, m.language, m.interfaceId, m.active);
    }
}
