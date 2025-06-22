// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract DesignPrincipleEnforcer {
    address public owner;
    bool public paused;

    mapping(address => bool) public approvedModules;
    mapping(address => bool) public operators;

    event Executed(address indexed module, bytes4 selector, address caller);
    event Paused(bool status);
    event OperatorAdded(address indexed operator);
    event ModuleApproved(address indexed module);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender], "Not operator");
        _;
    }

    modifier notPaused() {
        require(!paused, "System is paused");
        _;
    }

    constructor() {
        owner = msg.sender;
        operators[msg.sender] = true;
    }

    function setPaused(bool status) external onlyOwner {
        paused = status;
        emit Paused(status);
    }

    function approveModule(address module) external onlyOwner {
        approvedModules[module] = true;
        emit ModuleApproved(module);
    }

    function addOperator(address op) external onlyOwner {
        operators[op] = true;
        emit OperatorAdded(op);
    }

    function executeModule(address module, bytes calldata data)
        external
        onlyOperator
        notPaused
        returns (bytes memory result)
    {
        require(approvedModules[module], "Module not approved");
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }

        (bool success, bytes memory output) = module.delegatecall(data);
        require(success, "Execution failed");

        emit Executed(module, selector, msg.sender);
        return output;
    }

    receive() external payable {}
}
