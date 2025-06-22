// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureGateway {
    address public owner;
    mapping(address => bool) public approved;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyApproved() {
        require(approved[msg.sender], "Not approved");
        _;
    }

    function setApproved(address user, bool status) external {
        require(msg.sender == owner, "Not owner");
        approved[user] = status;
    }

    function gateway(address to, bytes calldata data) external onlyApproved {
        (bool success, ) = to.call(data);
        require(success, "Forward failed");
    }
}
