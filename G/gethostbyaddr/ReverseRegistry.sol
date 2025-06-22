// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReverseRegistry {
    mapping(address => string) public reverseNames;

    function registerName(string calldata name) external {
        reverseNames[msg.sender] = name;
    }

    function getName(address addr) external view returns (string memory) {
        return reverseNames[addr];
    }
}
