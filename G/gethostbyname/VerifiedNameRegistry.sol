// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VerifiedNameRegistry {
    address public admin;
    mapping(string => address) private nameToAddress;
    mapping(string => bool) public registered;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Unauthorized");
        _;
    }

    function registerName(string calldata name, address user) external onlyAdmin {
        require(!registered[name], "Already registered");
        nameToAddress[name] = user;
        registered[name] = true;
    }

    function getAddress(string calldata name) external view returns (address) {
        return nameToAddress[name];
    }
}
