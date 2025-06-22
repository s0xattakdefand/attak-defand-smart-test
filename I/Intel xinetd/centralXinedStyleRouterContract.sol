// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract XinetdRouter {
    address public owner;

    mapping(bytes4 => address) public services;

    event ServiceRegistered(bytes4 indexed selector, address indexed target);
    event Routed(address indexed user, bytes4 indexed selector);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerService(bytes4 selector, address target) external onlyOwner {
        services[selector] = target;
        emit ServiceRegistered(selector, target);
    }

    fallback() external payable {
        address target = services[msg.sig];
        require(target != address(0), "Unknown service");

        emit Routed(msg.sender, msg.sig);

        (bool success, ) = target.delegatecall(msg.data);
        require(success, "Service call failed");
    }
}
