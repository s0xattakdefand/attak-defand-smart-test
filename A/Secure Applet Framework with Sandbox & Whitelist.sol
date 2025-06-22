// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Trusted applet with controlled logic
contract TrustedApplet {
    uint256 public appletData;

    function updateData(uint256 newData) public {
        appletData = newData;
    }
}

contract AppletManager {
    address public owner;
    mapping(address => bool) public trustedApplets;

    event AppletExecuted(address applet, bytes data);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized");
        _;
    }

    // Register only trusted applets
    function addApplet(address applet) public onlyOwner {
        trustedApplets[applet] = true;
    }

    // Only owner can invoke and only on whitelisted logic
    function safeExecute(address applet, bytes calldata payload) public onlyOwner {
        require(trustedApplets[applet], "Applet not trusted");

        (bool success, ) = applet.call(payload); // call, not delegatecall
        require(success, "Applet call failed");

        emit AppletExecuted(applet, payload);
    }
}
