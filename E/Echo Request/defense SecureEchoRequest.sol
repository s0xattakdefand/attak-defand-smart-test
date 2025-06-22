// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureEchoRequest is ReentrancyGuard {
    event EchoRequestReceived(address indexed sender, string data);

    mapping(address => uint256) public lastRequestTime;
    uint256 public fee = 0.0005 ether;
    uint256 public cooldown = 60;

    function echoRequest(string calldata message) external payable nonReentrant {
        require(msg.value >= fee, "Insufficient fee");
        require(block.timestamp >= lastRequestTime[msg.sender] + cooldown, "Cooldown not over");

        lastRequestTime[msg.sender] = block.timestamp;
        emit EchoRequestReceived(msg.sender, message);
    }
}
