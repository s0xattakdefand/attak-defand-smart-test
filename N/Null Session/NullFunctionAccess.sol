// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract NullFunctionAccess {
    string public secret;

    function setSecret(string calldata data) external {
        secret = data; // ❌ No access control
    }
}
