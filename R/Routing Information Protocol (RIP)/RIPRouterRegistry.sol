// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract RIPRouterRegistry {
    struct Route {
        address target;
        uint8 hopCount;
    }

    mapping(address => mapping(bytes4 => Route)) public routes;

    event RouteRegistered(address indexed source, bytes4 indexed selector, address target, uint8 hops);

    function registerRoute(bytes4 selector, address target, uint8 hopCount) external {
        routes[msg.sender][selector] = Route(target, hopCount);
        emit RouteRegistered(msg.sender, selector, target, hopCount);
    }

    function getRoute(address from, bytes4 selector) external view returns (Route memory) {
        return routes[from][selector];
    }
}
