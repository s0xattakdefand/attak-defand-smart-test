// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ArchitectureFrameworkCore - Secure execution & modular routing framework

contract ArchitectureFrameworkCore {
    address public admin;
    bool public paused;

    mapping(address => bool) public isOperator;
    mapping(bytes4 => address) public selectorToModule;
    mapping(address => bool) public approvedModules;

    event ModuleApproved(address indexed module);
    event SelectorMapped(bytes4 indexed selector, address indexed module);
    event ExecutionRouted(address indexed module, bytes4 selector, address caller);
    event Paused(bool status);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyOperator() {
        require(isOperator[msg.sender], "Not operator");
        _;
    }

    modifier notPaused() {
        require(!paused, "Execution paused");
        _;
    }

    constructor() {
        admin = msg.sender;
        isOperator[msg.sender] = true;
    }

    // Admin: Approve modules and selectors
    function approveModule(address module) external onlyAdmin {
        approvedModules[module] = true;
        emit ModuleApproved(module);
    }

    function mapSelectorToModule(bytes4 selector, address module) external onlyAdmin {
        require(approvedModules[module], "Module not approved");
        selectorToModule[selector] = module;
        emit SelectorMapped(selector, module);
    }

    function setPaused(bool status) external onlyAdmin {
        paused = status;
        emit Paused(status);
    }

    function addOperator(address op) external onlyAdmin {
        isOperator[op] = true;
    }

    // Execution entry point
    function execute(bytes calldata data) external onlyOperator notPaused returns (bytes memory) {
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }

        address module = selectorToModule[selector];
        require(module != address(0), "Selector not mapped");

        (bool success, bytes memory result) = module.delegatecall(data);
        require(success, "Execution failed");

        emit ExecutionRouted(module, selector, msg.sender);
        return result;
    }

    receive() external payable {}
}
