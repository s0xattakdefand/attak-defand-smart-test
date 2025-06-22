// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Defense Scenario:
 * A contract that stores a short-lived session token (cookie),
 * includes an expiration time, and optionally a signature check 
 * to confirm the user => avoids indefinite or easily forged cookies.
 */
contract SecureCookieSession {
    struct CookieInfo {
        string data;
        uint256 expiry;
    }

    mapping(address => CookieInfo) public sessionCookie;

    // Admin or user can set a cookie with a short TTL
    function setCookie(string calldata data, uint256 ttlSeconds) external {
        require(ttlSeconds <= 3600, "Max 1 hour TTL"); // example cap
        uint256 expiry = block.timestamp + ttlSeconds;

        sessionCookie[msg.sender] = CookieInfo({
            data: data,
            expiry: expiry
        });
    }

    // Anyone can read, but also check if expired
    function getCookie(address user) external view returns (string memory) {
        CookieInfo memory c = sessionCookie[user];
        if (block.timestamp > c.expiry) {
            // expired
            return "";
        }
        return c.data;
    }

    // Clears the cookie to forcibly log user out 
    function clearCookie() external {
        delete sessionCookie[msg.sender];
    }
}
