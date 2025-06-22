// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SecureEGPRegistry
 * @notice A secure routing registry with role-based access control.
 *         Only accounts with ROUTE_ADMIN role can add or update routes.
 */
contract SecureEGPRegistry is AccessControl {
    bytes32 public constant ROUTE_ADMIN = keccak256("ROUTE_ADMIN");

    struct Route {
        uint256 asNumber;
        string destination;
        address nextHop;
        uint256 metric;
    }

    Route[] public routes;

    event RouteAdded(uint256 asNumber, string destination, address nextHop, uint256 metric);
    event RouteUpdated(uint256 index, uint256 asNumber, string destination, address nextHop, uint256 metric);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ROUTE_ADMIN, admin);
    }

    /**
     * @notice Adds a new route. Only accounts with ROUTE_ADMIN role can call.
     */
    function addRoute(
        uint256 asNumber,
        string calldata destination,
        address nextHop,
        uint256 metric
    ) external onlyRole(ROUTE_ADMIN) {
        routes.push(Route(asNumber, destination, nextHop, metric));
        emit RouteAdded(asNumber, destination, nextHop, metric);
    }

    /**
     * @notice Updates an existing route by index. Only ROUTE_ADMIN can call.
     */
    function updateRoute(
        uint256 index,
        uint256 asNumber,
        string calldata destination,
        address nextHop,
        uint256 metric
    ) external onlyRole(ROUTE_ADMIN) {
        require(index < routes.length, "Invalid index");
        routes[index] = Route(asNumber, destination, nextHop, metric);
        emit RouteUpdated(index, asNumber, destination, nextHop, metric);
    }

    /**
     * @notice Returns the total number of routes.
     */
    function getRouteCount() external view returns (uint256) {
        return routes.length;
    }
}
