// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Malicious payload contract
contract MaliciousPayload {
    uint256 public data;

    function attack() public {
        data = 999; // could do anything malicious here
    }
}

// Vulnerable contract using delegatecall
contract VulnerableActiveContent {
    address public owner;
    address public lib;

    constructor(address _lib) {
        owner = msg.sender;
        lib = _lib;
    }

    // Allows any user to inject executable logic (active content)
    function execute(bytes calldata payload) public {
        (bool success, ) = lib.delegatecall(payload);
        require(success, "Delegatecall failed");
    }
}
