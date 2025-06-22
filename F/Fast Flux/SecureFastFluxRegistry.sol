// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SecureFastFluxRegistry
 * @notice A secured registry using role-based access control.
 * Only accounts with the ROUTE_ADMIN role can add or modify node entries or adjust the flux interval.
 */
contract SecureFastFluxRegistry is AccessControl {
    bytes32 public constant ROUTE_ADMIN = keccak256("ROUTE_ADMIN");
    address[] public fluxNodes;
    uint256 public fluxInterval;

    event NodeAdded(address indexed newNode);
    event FluxIntervalUpdated(uint256 newInterval);

    constructor(address admin, uint256 _fluxInterval) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ROUTE_ADMIN, admin);
        fluxInterval = _fluxInterval;
    }

    /// @notice Only authorized administrators can add nodes.
    function addNode(address node) external onlyRole(ROUTE_ADMIN) {
        require(node != address(0), "Invalid address");
        fluxNodes.push(node);
        emit NodeAdded(node);
    }

    /// @notice Only authorized administrators can update the flux interval.
    function updateFluxInterval(uint256 newInterval) external onlyRole(ROUTE_ADMIN) {
        require(newInterval > 0, "Invalid interval");
        fluxInterval = newInterval;
        emit FluxIntervalUpdated(newInterval);
    }

    /// @notice Returns the active node computed from the current time.
    function getActiveNode() public view returns (address) {
        require(fluxNodes.length > 0, "No flux nodes available");
        uint256 index = (block.timestamp / fluxInterval) % fluxNodes.length;
        return fluxNodes[index];
    }
}
