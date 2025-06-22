// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MacWhitelist {
    mapping(address => bool) public trustedDevices;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function setTrusted(address device, bool allowed) external {
        require(msg.sender == admin, "Not admin");
        trustedDevices[device] = allowed;
    }

    function performSecureAction() external {
        require(trustedDevices[msg.sender], "Not whitelisted");
        // Secure logic here
    }
}
