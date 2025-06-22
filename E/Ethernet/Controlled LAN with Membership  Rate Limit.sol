// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * A controlled approach: only whitelisted members can broadcast, 
 * and possibly we do a rate-limit or fee to discourage spam.
 */
contract ManagedLANBroadcast {
    mapping(address => bool) public isMember;
    uint256 public broadcastFee = 0.001 ether;
    uint256 public cooldown = 60;  // seconds

    mapping(address => uint256) public lastBroadcastTime;

    event Broadcast(address indexed from, bytes message);

    address public admin;

    constructor(address[] memory initialMembers) {
        admin = msg.sender;
        for (uint256 i = 0; i < initialMembers.length; i++) {
            isMember[initialMembers[i]] = true;
        }
    }

    function setMember(address user, bool status) external {
        require(msg.sender == admin, "Not admin");
        isMember[user] = status;
    }

    function setFee(uint256 fee) external {
        require(msg.sender == admin, "Not admin");
        broadcastFee = fee;
    }

    function setCooldown(uint256 cd) external {
        require(msg.sender == admin, "Not admin");
        cooldown = cd;
    }

    function broadcastMessage(bytes calldata message) external payable {
        require(isMember[msg.sender], "Not in LAN membership");
        require(msg.value >= broadcastFee, "Fee not paid");
        require(block.timestamp >= lastBroadcastTime[msg.sender] + cooldown, "Cooldown active");

        lastBroadcastTime[msg.sender] = block.timestamp;

        emit Broadcast(msg.sender, message);
    }
}
