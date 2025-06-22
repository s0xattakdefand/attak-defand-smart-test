// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuthTokenMapping {
    mapping(address => bytes32) public authToken;

    event TokenSet(address indexed user, bytes32 token);
    event TokenValidated(address indexed user, bool success);

    // Sets a token for the caller
    function setToken(bytes32 token) public {
        authToken[msg.sender] = token;
        emit TokenSet(msg.sender, token);
    }

    // Validates token for a given address
    function validateToken(address user, bytes32 token) public view returns (bool) {
        bool isValid = authToken[user] == token;
        return isValid;
    }

    // Optional: allow users to clear their token
    function clearToken() public {
        authToken[msg.sender] = 0x0;
    }
}
