// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SecurityGateway {
    address public admin;

    uint256 public totalCalls;
    uint256 public blockedCalls;
    uint256 public falsePositives;
    uint256 public maliciousBlocked;

    mapping(address => bool) public isBlocked;
    mapping(address => bool) public isAttacker;

    constructor() {
        admin = msg.sender;
    }

    function setAttacker(address user, bool status) external {
        require(msg.sender == admin, "Only admin");
        isAttacker[user] = status;
    }

    function setBlock(address user, bool status) external {
        require(msg.sender == admin, "Only admin");
        isBlocked[user] = status;
    }

    function protectedCall() external {
        totalCalls++;

        if (isBlocked[msg.sender]) {
            blockedCalls++;

            if (isAttacker[msg.sender]) {
                maliciousBlocked++;
            } else {
                falsePositives++;
            }

            revert("Access denied");
        }

        // Normal business logic
    }

    function getMOE() external view returns (
        uint256 detectionRate,
        uint256 falsePositiveRate,
        uint256 effectiveness
    ) {
        detectionRate = totalCalls > 0 ? (maliciousBlocked * 100) / totalCalls : 0;
        falsePositiveRate = blockedCalls > 0 ? (falsePositives * 100) / blockedCalls : 0;
        effectiveness = blockedCalls > 0 ? (maliciousBlocked * 100) / blockedCalls : 0;
    }
}
