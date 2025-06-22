// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach: not purely exponential, but e.g. wait time = baseDelay * log2(attempt)
 * or a custom weighting. 
 */
contract LogarithmicBackoff {
    mapping(address => uint256) public attemptCount;
    mapping(address => uint256) public nextAllowedTime;
    uint256 public baseDelay = 60;

    function doAction() external {
        require(block.timestamp >= nextAllowedTime[msg.sender], "Wait more");
        attemptCount[msg.sender]++;
        // compute wait using log2 or sqrt for slower growth
        uint256 wait = baseDelay * log2(attemptCount[msg.sender]);
        nextAllowedTime[msg.sender] = block.timestamp + wait;
    }

    // For demonstration, a small integer log2 approach:
    function log2(uint256 x) internal pure returns (uint256) {
        // quick approximate
        uint256 n;
        while (x > 1) {
            x >>= 1;
            n++;
        }
        return n;
    }
}
