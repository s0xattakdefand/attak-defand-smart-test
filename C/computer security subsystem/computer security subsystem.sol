// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISecuritySubsystem {
    function enforce(address caller, bytes4 selector, bytes calldata payload) external;
}

contract SecuritySubsystemManager {
    address public owner;
    mapping(string => address) public subsystemByName;
    string[] public activeSubsystems;

    event SubsystemInvoked(string name, address module);
    event SubsystemRegistered(string name, address module);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerSubsystem(string calldata name, address module) external onlyOwner {
        subsystemByName[name] = module;
        activeSubsystems.push(name);
        emit SubsystemRegistered(name, module);
    }

    function enforceAll(bytes calldata data) external {
        bytes4 selector = bytes4(data[:4]);
        for (uint256 i = 0; i < activeSubsystems.length; i++) {
            string memory name = activeSubsystems[i];
            address module = subsystemByName[name];
            ISecuritySubsystem(module).enforce(msg.sender, selector, data);
            emit SubsystemInvoked(name, module);
        }
    }

    function getSubsystem(string calldata name) external view returns (address) {
        return subsystemByName[name];
    }

    function getActive() external view returns (string[] memory) {
        return activeSubsystems;
    }
}
