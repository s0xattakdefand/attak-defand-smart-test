// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title NaiveEGPRegistry
 * @notice A simple routing registry analogous to EGP.
 *         This naive implementation allows anyone to add route entries.
 *         (Attack Pattern: Lack of validation / ACL makes it trivially exploitable.)
 */
contract NaiveEGPRegistry {
    struct Route {
        uint256 asNumber;    // Autonomous system number of the originator
        string destination;  // IP prefix or network destination (as string)
        address nextHop;     // Next-hop address for the route
        uint256 metric;      // Cost metric for the route
    }

    Route[] public routes;

    event RouteAdded(uint256 asNumber, string destination, address nextHop, uint256 metric);

    /**
     * @notice Anyone can add a route.
     */
    function addRoute(
        uint256 asNumber,
        string calldata destination,
        address nextHop,
        uint256 metric
    ) external {
        // No access control: any account can add false routes.
        routes.push(Route(asNumber, destination, nextHop, metric));
        emit RouteAdded(asNumber, destination, nextHop, metric);
    }

    /**
     * @notice Get number of routes.
     */
    function getRouteCount() external view returns (uint256) {
        return routes.length;
    }
}
