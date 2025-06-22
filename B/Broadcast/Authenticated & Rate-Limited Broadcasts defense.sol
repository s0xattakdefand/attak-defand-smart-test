// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureBroadcaster {
    using ECDSA for bytes32;

    address public admin;
    uint256 public cooldown = 60;

    mapping(address => uint256) public lastBroadcast;
    mapping(address => bool) public authorizedSender;

    event SecureBroadcast(address indexed sender, string topic, string message);

    constructor(address _admin) {
        admin = _admin;
        authorizedSender[_admin] = true;
    }

    modifier onlyAuthorized() {
        require(authorizedSender[msg.sender], "Not authorized");
        _;
    }

    modifier rateLimited() {
        require(block.timestamp > lastBroadcast[msg.sender] + cooldown, "Cooldown active");
        _;
    }

    function broadcast(string calldata topic, string calldata message) public onlyAuthorized rateLimited {
        emit SecureBroadcast(msg.sender, topic, message);
        lastBroadcast[msg.sender] = block.timestamp;
    }

    function setAuthorized(address sender, bool status) public {
        require(msg.sender == admin, "Only admin");
        authorizedSender[sender] = status;
    }

    function updateCooldown(uint256 newCooldown) public {
        require(msg.sender == admin, "Only admin");
        cooldown = newCooldown;
    }
}
