// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GasBandwidthOptimization {
    // ✅ Moved inside a proper contract
    mapping(address => uint32) public smallCounters;

    event CounterIncremented(address indexed user, uint32 newValue);

    function incrementCounter() public {
        smallCounters[msg.sender] += 1;
        emit CounterIncremented(msg.sender, smallCounters[msg.sender]);
    }

    function getMyCounter() public view returns (uint32) {
        return smallCounters[msg.sender];
    }
}
