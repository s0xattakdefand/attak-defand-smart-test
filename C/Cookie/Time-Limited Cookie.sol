// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Cookie Type 2 (Defense): 
 * - A session-like cookie with time-to-live (TTL)
 * - Expires after a set duration
 */
contract ExpiringCookie {
    struct CookieData {
        string content;
        uint256 expiry;
    }

    mapping(address => CookieData) public cookies;

    event CookieSet(address indexed user, string content, uint256 expiry);
    event CookieCleared(address indexed user);

    /**
     * @dev User sets a cookie that expires after `ttlSeconds`.
     * E.g., 300 => 5 minutes
     */
    function setCookie(string calldata content, uint256 ttlSeconds) external {
        require(ttlSeconds <= 3600, "Max TTL = 1 hour");
        uint256 expiry = block.timestamp + ttlSeconds;

        cookies[msg.sender] = CookieData({
            content: content,
            expiry: expiry
        });

        emit CookieSet(msg.sender, content, expiry);
    }

    /**
     * @dev Returns cookie content if unexpired, otherwise empty.
     */
    function getCookie(address user) external view returns (string memory) {
        CookieData memory c = cookies[user];
        if (block.timestamp > c.expiry) {
            // expired
            return "";
        }
        return c.content;
    }

    /**
     * @dev Clear the cookie, e.g. user logs out.
     */
    function clearCookie() external {
        delete cookies[msg.sender];
        emit CookieCleared(msg.sender);
    }
}
