// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SecureMulticastRegistry {
    address public admin;
    mapping(address => bool) public authorizedReceivers;

    constructor() {
        admin = msg.sender;
    }

    function setReceiver(address receiver, bool status) external {
        require(msg.sender == admin, "Only admin");
        authorizedReceivers[receiver] = status;
    }

    function safeMulticast(address[] calldata targets, bytes calldata payload) external {
        for (uint256 i = 0; i < targets.length; i++) {
            require(authorizedReceivers[targets[i]], "Not authorized");

            (bool ok, ) = targets[i].call(payload);
            require(ok, "Call failed");
        }
    }
}
