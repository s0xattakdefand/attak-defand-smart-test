// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A naive 'circuit' approach: 
 * Once locked, funds remain locked indefinitely 
 * if the participant never closes the channel.
 */
contract NaiveCircuitChannel {
    mapping(address => uint256) public lockedFunds;
    bool public circuitInUse;

    function lockCircuit() external payable {
        require(!circuitInUse, "Circuit busy");
        lockedFunds[msg.sender] += msg.value;
        circuitInUse = true;
    }

    function endCircuit() external {
        // ❌ If user doesn't call endCircuit, funds remain locked
        lockedFunds[msg.sender] = 0;
        circuitInUse = false;
    }
}
