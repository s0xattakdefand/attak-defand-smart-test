// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ArchitectureConstructCore {
    address public admin;

    mapping(bytes4 => address) public capabilityRegistry; // selector => logic module
    mapping(address => bool) public approvedModules;
    mapping(address => bool) public operators;

    event ModuleApproved(address indexed module);
    event CapabilityMapped(bytes4 indexed selector, address indexed module);
    event OperationExecuted(address indexed module, bytes4 selector);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender], "Not operator");
        _;
    }

    constructor() {
        admin = msg.sender;
        operators[admin] = true;
    }

    function setOperator(address op, bool status) external onlyAdmin {
        operators[op] = status;
    }

    function approveModule(address module) external onlyAdmin {
        approvedModules[module] = true;
        emit ModuleApproved(module);
    }

    function mapCapability(bytes4 selector, address module) external onlyAdmin {
        require(approvedModules[module], "Module not approved");
        capabilityRegistry[selector] = module;
        emit CapabilityMapped(selector, module);
    }

    function execute(bytes calldata data) external onlyOperator returns (bytes memory) {
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }

        address module = capabilityRegistry[selector];
        require(module != address(0), "Capability not mapped");

        (bool success, bytes memory result) = module.delegatecall(data);
        require(success, "Execution failed");

        emit OperationExecuted(module, selector);
        return result;
    }
}
