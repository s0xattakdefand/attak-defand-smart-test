// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract LoggingAspect {
    event AspectCalled(address indexed caller, bytes4 selector, bytes data);

    function foo(uint256 value) external {
        emit AspectCalled(msg.sender, msg.sig, abi.encode(value));
        // insert logic (e.g., forward call to logic contract)
    }
}
