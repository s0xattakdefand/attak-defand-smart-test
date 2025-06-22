pragma solidity ^0.8.21;

contract TimeLockPolicy {
    uint256 public unlockTime;
    address public admin;

    constructor(uint256 delayInSeconds) {
        admin = msg.sender;
        unlockTime = block.timestamp + delayInSeconds;
    }

    modifier onlyAfterUnlock() {
        require(block.timestamp >= unlockTime, "Access locked");
        _;
    }

    function criticalAction() external onlyAfterUnlock {
        // Protected logic
    }
}
