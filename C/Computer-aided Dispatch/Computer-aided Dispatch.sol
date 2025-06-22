// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ICADModule {
    function executeAction(string calldata category, address target) external;
}

contract CADDispatcher {
    address public admin;

    struct DispatchRecord {
        string category;
        address target;
        address module;
        uint256 timestamp;
    }

    mapping(bytes32 => bool) public dispatched;
    DispatchRecord[] public history;

    mapping(string => address) public categoryToModule;

    event DispatchTriggered(string category, address target, address module);
    event ModuleRegistered(string category, address module);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerModule(string calldata category, address module) external onlyAdmin {
        categoryToModule[category] = module;
        emit ModuleRegistered(category, module);
    }

    function dispatch(string calldata category, address target) external {
        bytes32 dispatchId = keccak256(abi.encodePacked(category, target, block.number));
        require(!dispatched[dispatchId], "Already dispatched");

        address module = categoryToModule[category];
        require(module != address(0), "No module for category");

        ICADModule(module).executeAction(category, target);

        history.push(DispatchRecord({
            category: category,
            target: target,
            module: module,
            timestamp: block.timestamp
        }));

        dispatched[dispatchId] = true;
        emit DispatchTriggered(category, target, module);
    }

    function getHistoryCount() external view returns (uint256) {
        return history.length;
    }
}
