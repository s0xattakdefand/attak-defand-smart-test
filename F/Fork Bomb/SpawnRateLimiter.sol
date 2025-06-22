// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SpawnRateLimiter {
    mapping(address => uint256) public lastSpawnTime;
    uint256 public cooldown = 60; // 60 seconds

    event Spawned(address indexed user, address newContract);

    function spawnContract() external {
        require(block.timestamp >= lastSpawnTime[msg.sender] + cooldown, "Cooldown active");
        lastSpawnTime[msg.sender] = block.timestamp;

        address newContract = address(new LightweightChild(msg.sender));
        emit Spawned(msg.sender, newContract);
    }
}

contract LightweightChild {
    address public creator;

    constructor(address _creator) {
        creator = _creator;
    }
}
