// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A circuit-switched style channel with forced time-based closure.
 * If user fails to endCircuit before the deadline, any party can forcibly close it.
 */
contract TimedCircuitChannel {
    struct Circuit {
        address owner;
        uint256 lockedAmount;
        uint256 startTime;
        uint256 duration;
        bool active;
    }

    Circuit public circuit;
    event CircuitOpened(address indexed user, uint256 amount, uint256 start, uint256 duration);
    event CircuitClosed(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == circuit.owner, "Not circuit owner");
        _;
    }

    function openCircuit(uint256 duration) external payable {
        require(!circuit.active, "Already in use");
        circuit = Circuit({
            owner: msg.sender,
            lockedAmount: msg.value,
            startTime: block.timestamp,
            duration: duration,
            active: true
        });
        emit CircuitOpened(msg.sender, msg.value, block.timestamp, duration);
    }

    function endCircuit() external onlyOwner {
        require(circuit.active, "No active circuit");
        _closeCircuit();
    }

    function forceCloseIfExpired() external {
        require(circuit.active, "No circuit");
        require(block.timestamp >= circuit.startTime + circuit.duration, "Not expired yet");
        _closeCircuit();
    }

    function _closeCircuit() internal {
        uint256 amount = circuit.lockedAmount;
        address user = circuit.owner;
        circuit.active = false;
        circuit.lockedAmount = 0;
        payable(user).transfer(amount);
        emit CircuitClosed(user, amount);
    }
}
