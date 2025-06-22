// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CookiesVulnerabilitiesAttackDefense - Full Attack and Defense Simulation for Cookie-like Vulnerabilities in Web3 Contracts
/// @author ChatGPT

/// @notice Secure session token contract (cookie-like management)
contract SecureCookieManager {
    address public owner;

    struct CookieSession {
        address user;
        uint256 createdAt;
        uint256 expiresAt;
        bool active;
        uint256 nonce;
    }

    mapping(bytes32 => CookieSession) public sessions;
    mapping(address => uint256) public userNonces;
    uint256 public cookieDuration = 10 minutes;

    event CookieCreated(bytes32 indexed cookieId, address indexed user);
    event CookieTerminated(bytes32 indexed cookieId);

    constructor() {
        owner = msg.sender;
    }

    function createCookieSession() external returns (bytes32 cookieId) {
        userNonces[msg.sender]++;
        cookieId = keccak256(
            abi.encodePacked(msg.sender, block.timestamp, block.number, userNonces[msg.sender])
        );

        sessions[cookieId] = CookieSession({
            user: msg.sender,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + cookieDuration,
            active: true,
            nonce: userNonces[msg.sender]
        });

        emit CookieCreated(cookieId, msg.sender);
    }

    function validateCookie(bytes32 _cookieId) external view returns (bool) {
        CookieSession memory c = sessions[_cookieId];
        return (c.active && c.expiresAt > block.timestamp && c.user == msg.sender);
    }

    function terminateCookie(bytes32 _cookieId) external {
        require(sessions[_cookieId].user == msg.sender, "Not cookie owner");
        sessions[_cookieId].active = false;
        emit CookieTerminated(_cookieId);
    }

    function invalidateAllCookies(address user) external {
        require(msg.sender == owner, "Only owner can invalidate globally");
        userNonces[user]++;
    }
}

/// @notice Attack contract trying to reuse or forge cookie sessions
contract CookieIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryReuseCookie(bytes32 stolenCookieId) external view returns (bool success) {
        (bool callSuccess, bytes memory result) = target.staticcall(
            abi.encodeWithSignature("validateCookie(bytes32)", stolenCookieId)
        );
        require(callSuccess, "Call failed");
        success = abi.decode(result, (bool));
    }
}
