pragma solidity ^0.8.21;

contract TokenLinkRouter {
    mapping(address => uint256) public cost;

    function setCost(address route, uint256 gasCost) external {
        cost[route] = gasCost;
    }

    function getBestRoute(address[] memory routes) external view returns (address best) {
        uint256 min = type(uint256).max;
        for (uint i = 0; i < routes.length; i++) {
            if (cost[routes[i]] < min) {
                min = cost[routes[i]];
                best = routes[i];
            }
        }
    }
}
