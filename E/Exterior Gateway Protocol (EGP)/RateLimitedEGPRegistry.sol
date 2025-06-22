// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract RateLimitedEGPRegistry is AccessControl {
    bytes32 public constant ROUTE_ADMIN = keccak256("ROUTE_ADMIN");

    struct Route {
        uint256 asNumber;
        string destination;
        address nextHop;
        uint256 metric;
    }

    Route[] public routes;
    mapping(address => uint256) public lastRouteTime;
    uint256 public constant COOLDOWN = 300; // 5 minutes cooldown

    event RouteAdded(uint256 asNumber, string destination, address nextHop, uint256 metric);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ROUTE_ADMIN, admin);
    }

    function addRoute(
        uint256 asNumber,
        string calldata destination,
        address nextHop,
        uint256 metric
    ) external onlyRole(ROUTE_ADMIN) {
        require(block.timestamp >= lastRouteTime[msg.sender] + COOLDOWN, "Rate limit exceeded");
        lastRouteTime[msg.sender] = block.timestamp;

        routes.push(Route(asNumber, destination, nextHop, metric));
        emit RouteAdded(asNumber, destination, nextHop, metric);
    }
}
