// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ASICActivityMonitor {
    mapping(address => uint256) public lastCallBlock;
    mapping(address => uint256) public callCount;
    uint256 public callThreshold = 3;

    event ASICPatternDetected(address indexed actor, uint256 count);
    event Allowed(address indexed actor);

    modifier antiASIC(bytes calldata data) {
        // Rate limit detection
        if (lastCallBlock[msg.sender] == block.number) {
            callCount[msg.sender]++;
            if (callCount[msg.sender] > callThreshold) {
                emit ASICPatternDetected(msg.sender, callCount[msg.sender]);
                revert("ASIC-like behavior blocked");
            }
        } else {
            callCount[msg.sender] = 1;
            lastCallBlock[msg.sender] = block.number;
        }

        emit Allowed(msg.sender);
        _;
    }

    function protectedFunction(bytes calldata data) external antiASIC(data) returns (string memory) {
        // Simulated business logic
        return "Processed by non-ASIC";
    }
}
