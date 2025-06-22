// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title LoopbackCaller - Demonstrates calling itself via `this.call`
contract LoopbackCaller {
    event CalledBySelf(address indexed from);

    function callSelf() external returns (bool) {
        (bool success, ) = address(this).call(
            abi.encodeWithSignature("loopbackHandler()")
        );
        require(success, "Self-call failed");
        return success;
    }

    function loopbackHandler() public {
        require(msg.sender == address(this), "Must be internal call");
        emit CalledBySelf(msg.sender);
    }
}
