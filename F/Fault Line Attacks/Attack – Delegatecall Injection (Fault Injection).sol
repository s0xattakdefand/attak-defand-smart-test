// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK PATTERN:
 * The vulnerable contract blindly delegatecalls into a library.
 * If the attacker controls the implementation address, they can overwrite storage.
 */

contract VulnerableDelegator {
    address public implementation;
    address public owner;

    constructor(address _impl) {
        implementation = _impl;
        owner = msg.sender;
    }

    fallback() external payable {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success, "Delegatecall failed");
    }
}
