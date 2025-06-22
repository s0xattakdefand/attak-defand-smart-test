// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ICNOHandler {
    function handleCNO(string calldata kind, address actor, bytes calldata payload) external;
}

contract CNOCoordinator {
    address public admin;
    mapping(string => address) public cnoModules;
    event CNOExecuted(string kind, address indexed actor, address module);
    event ModuleRegistered(string kind, address module);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerModule(string calldata kind, address module) external onlyAdmin {
        cnoModules[kind] = module;
        emit ModuleRegistered(kind, module);
    }

    function executeCNO(string calldata kind, bytes calldata payload) external {
        address module = cnoModules[kind];
        require(module != address(0), "No module registered");
        ICNOHandler(module).handleCNO(kind, msg.sender, payload);
        emit CNOExecuted(kind, msg.sender, module);
    }

    function getModule(string calldata kind) external view returns (address) {
        return cnoModules[kind];
    }
}
