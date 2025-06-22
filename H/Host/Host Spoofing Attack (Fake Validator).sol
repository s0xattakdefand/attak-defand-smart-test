// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FakeHostSpoof {
    function validateData(bytes calldata input) external view returns (bool) {
        return true; // 🚨 Always returns true — acts as "host"
    }
}
