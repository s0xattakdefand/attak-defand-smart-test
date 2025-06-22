// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VerifiedForwardLookup {
    mapping(string => address) private nameToAddress;
    mapping(string => bool) public registered;
    address public admin;

    event Registered(string name, address addr);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    function register(string calldata name, address user) external onlyAdmin {
        require(!registered[name], "Already registered");
        nameToAddress[name] = user;
        registered[name] = true;
        emit Registered(name, user);
    }

    function resolve(string calldata name) external view returns (address) {
        return nameToAddress[name];
    }
}
