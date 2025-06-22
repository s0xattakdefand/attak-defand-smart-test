pragma solidity ^0.8.21;

interface ITarget {
    function process(bytes calldata) external;
}

contract DynamicForwarder {
    address public admin;
    mapping(string => address) public services;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function setService(string memory name, address target) external onlyAdmin {
        services[name] = target;
    }

    function forwardTo(string memory name, bytes calldata data) external {
        require(services[name] != address(0), "Target not registered");
        ITarget(services[name]).process(data);
    }
}
