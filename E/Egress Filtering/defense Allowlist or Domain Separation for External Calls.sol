// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * A contract that maintains an allowlist of addresses 
 * to which it can make external calls, preventing calls to arbitrary addresses.
 */
contract AllowedEgressFiltering {
    mapping(address => bool) public allowedTargets;
    address public admin;

    event ExternalCall(address indexed target, bytes data, bool success);
    event TargetAllowed(address indexed target, bool status);

    constructor() {
        admin = msg.sender;
    }

    function setAllowedTarget(address target, bool status) external {
        require(msg.sender == admin, "Not admin");
        allowedTargets[target] = status;
        emit TargetAllowed(target, status);
    }

    function callExternal(address target, bytes calldata data) external {
        require(allowedTargets[target], "Target not allowed");
        (bool success, ) = target.call(data);
        emit ExternalCall(target, data, success);
    }
}
