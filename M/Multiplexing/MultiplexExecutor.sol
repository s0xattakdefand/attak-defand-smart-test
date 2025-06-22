// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MultiplexExecutor {
    event ActionExecuted(address target, bytes data);

    function executeBatch(address[] calldata targets, bytes[] calldata payloads) external {
        require(targets.length == payloads.length, "Length mismatch");

        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, ) = targets[i].call(payloads[i]);
            require(ok, "Subcall failed");
            emit ActionExecuted(targets[i], payloads[i]);
        }
    }
}
