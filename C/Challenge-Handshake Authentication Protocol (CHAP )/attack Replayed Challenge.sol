// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A naive CHAP-like approach. 
 * Attack: The challenge never changes => attacker replays old valid responses.
 */
contract NaiveCHAP {
    bytes32 public challenge = keccak256("static-challenge");
    mapping(address => bool) public isAuthenticated;

    function respond(bytes32 response) external {
        // ❌ No uniqueness => once known, attacker can reuse old response
        if (response == keccak256(abi.encodePacked(msg.sender, challenge))) {
            isAuthenticated[msg.sender] = true;
        }
    }
}
