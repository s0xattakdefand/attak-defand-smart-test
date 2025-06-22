// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach:
 * A pseudo-switch that routes data from one address to another 
 * if a route is known or whitelisted, akin to a layer-2 or bridging approach.
 */
contract PseudoSwitch {
    mapping(address => mapping(address => bool)) public routeAllowed;

    event DataRouted(address from, address to, bytes data);

    function setRoute(address from, address to, bool allowed) external {
        // In production, you'd do admin checks
        routeAllowed[from][to] = allowed;
    }

    function routeData(address to, bytes calldata data) external {
        require(routeAllowed[msg.sender][to], "Route not allowed");
        // we simulate a 'send' by just logging
        emit DataRouted(msg.sender, to, data);
    }
}
