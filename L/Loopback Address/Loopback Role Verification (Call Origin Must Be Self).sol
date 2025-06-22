pragma solidity ^0.8.21;

contract LoopbackGuard {
    modifier onlySelf() {
        require(msg.sender == address(this), "Must be internal loopback");
        _;
    }

    function criticalFunction() external onlySelf {
        // internal-only logic
    }

    function initiate() external {
        // perform loopback
        this.criticalFunction();
    }
}
