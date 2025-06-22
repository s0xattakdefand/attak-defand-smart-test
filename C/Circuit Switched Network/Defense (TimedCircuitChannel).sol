// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TimedCircuitChannel
 * Defense Type: Time-limited circuit with forced release
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

    /**
     * @dev Open a circuit for a specified duration in seconds, 
     * user must deposit ETH. After the duration, 
     * circuit can be forced closed by anyone.
     */
    function openCircuit(uint256 duration) external payable {
        require(!circuit.active, "Circuit in use");
        require(msg.value > 0, "Must lock some ETH");

        circuit = Circuit({
            owner: msg.sender,
            lockedAmount: msg.value,
            startTime: block.timestamp,
            duration: duration,
            active: true
        });

        emit CircuitOpened(msg.sender, msg.value, block.timestamp, duration);
    }

    /**
     * @dev The owner can voluntarily end the circuit early.
     */
    function endCircuit() external onlyOwner {
        require(circuit.active, "No active circuit");
        _closeCircuit();
    }

    /**
     * @dev Anyone can force close if the circuit has expired.
     */
    function forceCloseIfExpired() external {
        require(circuit.active, "No circuit to close");
        require(block.timestamp >= circuit.startTime + circuit.duration, "Circuit not expired");
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
