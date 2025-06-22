// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NoAuthentication {
    address public secretOwner;
    string private secret = "Top Secret";

    constructor() {
        secretOwner = msg.sender;
    }

    // ❌ Anyone can call and change ownership!
    function updateSecretOwner(address newOwner) public {
        secretOwner = newOwner;
    }

    function readSecret() public view returns (string memory) {
        return secret;
    }
}
