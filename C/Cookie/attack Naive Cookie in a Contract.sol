// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Attack Scenario: 
 * This contract tries to store ephemeral user sessions (like cookies) 
 * but does not validate or expire them properly.
 */
contract NaiveCookieSession {
    // Session data mapped by user => a random token or string
    mapping(address => string) public sessionCookie;

    // Anyone can set or overwrite their session cookie
    function setCookie(string calldata data) external {
        sessionCookie[msg.sender] = data; 
    }

    // Basic read
    function getCookie(address user) external view returns (string memory) {
        return sessionCookie[user];
    }
}
