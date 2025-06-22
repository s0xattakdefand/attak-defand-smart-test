// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract zkSemaphoreRegistry {
    mapping(uint256 => bool) public validRoots;

    function registerRoot(uint256 root) external {
        validRoots[root] = true;
    }

    function isValidRoot(uint256 root) external view returns (bool) {
        return validRoots[root];
    }
}
