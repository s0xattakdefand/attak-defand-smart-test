// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStorageModule {
    function getBalance(address user) external view returns (uint256);
}

contract DataChecker {
    address public module;

    constructor(address _mod) {
        module = _mod;
    }

    function isUncorrupted(address user, uint256 expected) external view returns (bool) {
        return IStorageModule(module).getBalance(user) == expected;
    }
}
