// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuthTokenProof {
    mapping(address => bytes32) public authHash;

    function submitHashedToken(bytes32 hash) external {
        authHash[msg.sender] = hash;
    }

    function verifyToken(string calldata token) external view returns (bool) {
        return authHash[msg.sender] == keccak256(abi.encodePacked(token));
    }
}
