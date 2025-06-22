// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Cookie Type 1 (Attack): Indefinite, naive cookie storage
 * - No expiration, no security checks
 */
contract NaiveCookie {
    // Map user => cookie string (could be a session token)
    mapping(address => string) public userCookie;

    /**
     * @dev User sets an indefinite cookie. 
     * Attack: no expiration => attacker can read or replay if dApp uses it.
     */
    function setCookie(string calldata data) external {
        userCookie[msg.sender] = data;
    }

    /**
     * @dev Return stored cookie for a user.
     */
    function getCookie(address user) external view returns (string memory) {
        return userCookie[user];
    }
}
