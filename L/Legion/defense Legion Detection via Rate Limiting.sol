pragma solidity ^0.8.21;

contract RateLimiter {
    mapping(address => uint256) public lastInteraction;
    uint256 public constant DELAY = 10 seconds;

    modifier notTooFast() {
        require(block.timestamp - lastInteraction[msg.sender] >= DELAY, "Slow down");
        lastInteraction[msg.sender] = block.timestamp;
        _;
    }

    function sensitiveAction() external notTooFast {
        // Rate-limited action
    }
}
