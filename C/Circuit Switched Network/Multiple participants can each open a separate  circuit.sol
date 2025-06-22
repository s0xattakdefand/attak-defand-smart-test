// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MultiPartyCircuit
 * Other Type: Multi-party circuit approach, multiple concurrent 'lines'
 */
contract MultiPartyCircuit {
    struct CircuitInfo {
        address user;
        uint256 lockedAmount;
        bool active;
    }

    // Each circuit has an ID, can be used in parallel
    mapping(uint256 => CircuitInfo) public circuits;
    uint256 public nextCircuitId;

    event CircuitOpened(uint256 circuitId, address user, uint256 amount);
    event CircuitClosed(uint256 circuitId, address user, uint256 amount);

    /**
     * @dev Opens a new circuit with a unique ID.
     */
    function openCircuit() external payable {
        require(msg.value > 0, "Must send ETH");
        circuits[nextCircuitId] = CircuitInfo({
            user: msg.sender,
            lockedAmount: msg.value,
            active: true
        });

        emit CircuitOpened(nextCircuitId, msg.sender, msg.value);
        nextCircuitId++;
    }

    /**
     * @dev Closes a specific circuit ID if the caller is the user.
     */
    function closeCircuit(uint256 circuitId) external {
        CircuitInfo storage c = circuits[circuitId];
        require(c.active, "Circuit not active");
        require(c.user == msg.sender, "Not your circuit");

        c.active = false;
        uint256 amount = c.lockedAmount;
        c.lockedAmount = 0;
        
        payable(msg.sender).transfer(amount);
        emit CircuitClosed(circuitId, msg.sender, amount);
    }
}
