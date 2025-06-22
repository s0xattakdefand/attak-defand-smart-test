// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WhitelistedForwardProxy {
    address public admin;
    mapping(address => bool) public approvedTargets;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function approveTarget(address target, bool approved) external onlyAdmin {
        approvedTargets[target] = approved;
    }

    function forward(address target, bytes calldata data) external returns (bytes memory) {
        require(approvedTargets[target], "Target not allowed");
        (bool success, bytes memory result) = target.call(data);
        require(success, "Forward failed");
        return result;
    }
}
