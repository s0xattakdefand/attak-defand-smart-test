// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Cookie Type 3 (Other): Hashed cookie approach
 * - Store only a hash of the cookie to hide actual content on-chain
 */
contract HashedCookie {
    // user => hash of their cookie (like keccak256 of session token)
    mapping(address => bytes32) public cookieHash;

    /**
     * @dev User sets the hashed cookie. 
     *     Off-chain, they compute hash = keccak256(cookieContent).
     */
    function setCookieHash(bytes32 hashValue) external {
        cookieHash[msg.sender] = hashValue;
    }

    /**
     * @dev Verify off-chain if keccak256(cookieContent) == cookieHash[user].
     * Contract doesn't store the plaintext cookie => privacy for session data
     */
    function getCookieHash(address user) external view returns (bytes32) {
        return cookieHash[user];
    }
}
