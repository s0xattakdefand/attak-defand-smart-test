// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AllowedEgressFiltering {
    address public admin;
    mapping(address => bool) public allowed;

    event ExternalCall(address indexed target, bytes data, bool success);

    constructor() {
        admin = msg.sender;
    }

    function setAllowed(address target, bool isAllowed) external {
        require(msg.sender == admin, "Not admin");
        allowed[target] = isAllowed;
    }

    function callExternal(address target, bytes calldata data) external {
        require(allowed[target], "Target not allowed");
        (bool success, ) = target.call(data);
        emit ExternalCall(target, data, success);
    }
}
