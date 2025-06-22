// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract NetworkDivisionManager {
    struct Module {
        string name;
        address addr;
        uint8 divisionType; // 1 = Router, 2 = Relayer, 3 = Monitor, etc.
        bool active;
    }

    mapping(bytes32 => Module) public modules;
    bytes32[] public registeredModules;

    event ModuleRegistered(string name, address indexed addr, uint8 divisionType);
    event ModuleCalled(address indexed target, bytes4 selector, uint256 timestamp);
    event ModuleDisabled(address indexed addr);

    modifier onlyActiveModule(bytes32 id) {
        require(modules[id].active, "Module not active");
        _;
    }

    function registerModule(string calldata name, address addr, uint8 divisionType) external {
        bytes32 id = keccak256(abi.encodePacked(name, addr));
        require(modules[id].addr == address(0), "Already registered");
        modules[id] = Module(name, addr, divisionType, true);
        registeredModules.push(id);
        emit ModuleRegistered(name, addr, divisionType);
    }

    function disableModule(bytes32 id) external {
        require(modules[id].addr != address(0), "Not found");
        modules[id].active = false;
        emit ModuleDisabled(modules[id].addr);
    }

    function callModule(bytes32 id, bytes calldata data) external onlyActiveModule(id) {
        address target = modules[id].addr;
        require(target != address(0), "Unknown module");

        (bool success, ) = target.call(data);
        require(success, "Module call failed");

        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }

        emit ModuleCalled(target, selector, block.timestamp);
    }

    function getAllModules() external view returns (Module[] memory out) {
        uint256 len = registeredModules.length;
        out = new Module[](len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = modules[registeredModules[i]];
        }
    }
}
