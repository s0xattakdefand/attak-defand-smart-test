// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ModuleHub {
    mapping(bytes4 => address) public moduleBySelector;
    address public admin;

    event Routed(bytes4 selector, address module);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function setModule(bytes4 selector, address module) external onlyAdmin {
        moduleBySelector[selector] = module;
        emit Routed(selector, module);
    }

    function execute(bytes4 selector, bytes calldata data) external returns (bytes memory) {
        address target = moduleBySelector[selector];
        require(target != address(0), "Unknown selector");
        (bool ok, bytes memory res) = target.delegatecall(data);
        require(ok, "Delegatecall failed");
        return res;
    }
}
