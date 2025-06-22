// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title NaiveFastFluxRegistry
 * @notice An insecure implementation where anyone can add flux nodes.
 * This is considered an ATTACK pattern because it lacks any access control.
 */
contract NaiveFastFluxRegistry {
    address[] public fluxNodes;
    uint256 public fluxInterval;

    event NodeAdded(address indexed newNode);
    event FluxIntervalUpdated(uint256 newInterval);

    constructor(uint256 _fluxInterval) {
        fluxInterval = _fluxInterval;
    }

    /// @notice Anyone can add a node – no restrictions.
    function addNode(address node) external {
        require(node != address(0), "Invalid address");
        fluxNodes.push(node);
        emit NodeAdded(node);
    }

    /// @notice Update the flux interval – no access control.
    function updateFluxInterval(uint256 newInterval) external {
        require(newInterval > 0, "Invalid interval");
        fluxInterval = newInterval;
        emit FluxIntervalUpdated(newInterval);
    }

    /// @notice Returns the current active node based on block.timestamp.
    function getActiveNode() public view returns (address) {
        require(fluxNodes.length > 0, "No flux nodes available");
        uint256 index = (block.timestamp / fluxInterval) % fluxNodes.length;
        return fluxNodes[index];
    }
}
