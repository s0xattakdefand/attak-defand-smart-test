// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title NaiveCircuitChannel
 * Attack Type: Perpetual circuit lock with no forced release
 */
contract NaiveCircuitChannel {
    mapping(address => uint256) public lockedFunds;
    bool public circuitInUse;

    event CircuitLocked(address indexed user, uint256 amount);
    event CircuitFreed(address indexed user, uint256 refunded);

    /**
     * @dev Lock the circuit by sending some ETH. 
     * No forced release mechanism => indefinite lock possible.
     */
    function lockCircuit() external payable {
        require(!circuitInUse, "Circuit busy");
        lockedFunds[msg.sender] += msg.value;
        circuitInUse = true;
        emit CircuitLocked(msg.sender, msg.value);
    }

    /**
     * @dev End the circuit, but only the user can do it, 
     * or else remains locked if user doesn't call.
     */
    function endCircuit() external {
        require(circuitInUse, "No circuit to end");
        uint256 amount = lockedFunds[msg.sender];
        require(amount > 0, "Not the circuit holder");
        
        lockedFunds[msg.sender] = 0;
        circuitInUse = false;

        payable(msg.sender).transfer(amount);
        emit CircuitFreed(msg.sender, amount);
    }
}
