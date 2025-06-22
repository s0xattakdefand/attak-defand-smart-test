// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BondedCircuit
 * Other Type: Bond-based reservation approach
 */
contract BondedCircuit {
    struct CircuitRes {
        address user;
        uint256 lockedBond;
        uint256 startTime;
        uint256 duration;
        bool active;
    }

    mapping(uint256 => CircuitRes) public circuits;
    uint256 public nextCircuitId;
    uint256 public slashAmount = 0.01 ether; // penalty if user fails to close

    event CircuitBonded(uint256 circuitId, address user, uint256 bond);
    event CircuitReleased(uint256 circuitId, address user, uint256 refunded);
    event CircuitSlashed(uint256 circuitId, address user, uint256 penalty);

    function openCircuitBond(uint256 duration) external payable {
        require(msg.value >= slashAmount, "Insufficient bond");
        circuits[nextCircuitId] = CircuitRes({
            user: msg.sender,
            lockedBond: msg.value,
            startTime: block.timestamp,
            duration: duration,
            active: true
        });

        emit CircuitBonded(nextCircuitId, msg.sender, msg.value);
        nextCircuitId++;
    }

    function releaseCircuit(uint256 circuitId) external {
        CircuitRes storage c = circuits[circuitId];
        require(c.active, "Not active");
        require(c.user == msg.sender, "Not circuit user");

        c.active = false;
        uint256 bond = c.lockedBond;
        c.lockedBond = 0;

        // Full bond returned
        payable(msg.sender).transfer(bond);
        emit CircuitReleased(circuitId, msg.sender, bond);
    }

    function forceSlashIfExpired(uint256 circuitId) external {
        CircuitRes storage c = circuits[circuitId];
        require(c.active, "Circuit not active");
        require(block.timestamp > c.startTime + c.duration, "Not expired yet");

        c.active = false;
        uint256 bond = c.lockedBond;
        c.lockedBond = 0;

        // slash penalty
        if (bond >= slashAmount) {
            // slash and reward the slasher or keep in contract
            uint256 remainder = bond - slashAmount;
            // if we choose to give slash to the caller
            payable(msg.sender).transfer(slashAmount);
            payable(c.user).transfer(remainder);
            emit CircuitSlashed(circuitId, c.user, slashAmount);
        } else {
            // bond too small, slash it all
            payable(msg.sender).transfer(bond);
            emit CircuitSlashed(circuitId, c.user, bond);
        }
    }
}
