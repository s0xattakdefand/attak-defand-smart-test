// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BatchExecutionFrame {
    event ActionExecuted(address indexed target, bytes data);

    function executeBatch(address[] calldata targets, bytes[] calldata payloads) external {
        require(targets.length == payloads.length, "Mismatched arrays");

        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, ) = targets[i].call(payloads[i]);
            require(success, "Execution failed");
            emit ActionExecuted(targets[i], payloads[i]);
        }
    }
}
