// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract RoleUsageLogger {
    mapping(bytes32 => mapping(bytes4 => uint256)) public roleUsage;

    event RoleUsageLogged(bytes32 indexed role, bytes4 indexed selector);

    function log(bytes32 role, bytes4 selector) external {
        roleUsage[role][selector]++;
        emit RoleUsageLogged(role, selector);
    }

    function getUsage(bytes32 role, bytes4 selector) external view returns (uint256) {
        return roleUsage[role][selector];
    }
}
