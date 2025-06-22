// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AddressFirewall {
    mapping(address => bool) public allowed;
    address public owner;
    uint256 public secret;

    modifier onlyAllowed() {
        require(allowed[msg.sender], "Blocked by firewall");
        _;
    }

    constructor() {
        owner = msg.sender;
        allowed[owner] = true;
    }

    function toggleAccess(address user, bool status) external {
        require(msg.sender == owner, "Not owner");
        allowed[user] = status;
    }

    function setSecret(uint256 _value) external onlyAllowed {
        secret = _value;
    }
}
