pragma solidity ^0.8.21;

interface IModule {
    function execute(bytes calldata input) external returns (bool);
}

contract ModularKernel {
    mapping(string => address) public modules;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function registerModule(string memory name, address moduleAddr) external {
        require(msg.sender == admin, "Only admin");
        modules[name] = moduleAddr;
    }

    function runModule(string memory name, bytes calldata input) external returns (bool) {
        require(modules[name] != address(0), "Module not registered");
        return IModule(modules[name]).execute(input);
    }
}
