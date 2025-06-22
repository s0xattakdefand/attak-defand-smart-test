// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * DEFENSE TYPE:
 * - We use a reentrancy guard if we do any callback
 * - We also add a rate limit or fee to deter spam
 */
contract SecureEchoRequest is ReentrancyGuard {
    event EchoRequestReceived(address indexed sender, string message);
    mapping(address => uint256) public lastRequestTime;
    uint256 public echoFee = 0.0005 ether; // small fee
    uint256 public cooldown = 60;         // 1 minute

    function setFee(uint256 newFee) external {
        // For demonstration, no real owner check, 
        // but in production you'd do onlyOwner or AccessControl
        echoFee = newFee;
    }

    function setCooldown(uint256 newCooldown) external {
        cooldown = newCooldown;
    }

    function echoRequest(string calldata message) external payable nonReentrant {
        // 1) Must pay a fee to call
        require(msg.value >= echoFee, "Insufficient fee");
        // 2) Rate limit
        require(block.timestamp >= lastRequestTime[msg.sender] + cooldown, "Cooldown active");

        lastRequestTime[msg.sender] = block.timestamp;
        emit EchoRequestReceived(msg.sender, message);

        // If we had a callback: 
        // ICaller(msg.sender).onEchoResponse(message); 
        // that would be protected by nonReentrant
    }
}
