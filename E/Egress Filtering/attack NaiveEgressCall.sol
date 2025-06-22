// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NaiveEgressCall {
    event ExternalCall(address indexed target, bytes data, bool success);

    function callExternal(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);
        emit ExternalCall(target, data, success);
    }
}
