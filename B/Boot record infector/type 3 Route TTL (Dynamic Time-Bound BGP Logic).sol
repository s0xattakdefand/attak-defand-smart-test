contract ExpiringRouteControl {
    struct Route {
        uint256 expiresAt;
        bool active;
    }

    mapping(address => Route) public routes;

    function announceRoute(address gateway, uint256 ttl) public {
        routes[gateway] = Route({expiresAt: block.timestamp + ttl, active: true});
    }

    function isActiveRoute(address gateway) public view returns (bool) {
        return routes[gateway].active && block.timestamp < routes[gateway].expiresAt;
    }
}
