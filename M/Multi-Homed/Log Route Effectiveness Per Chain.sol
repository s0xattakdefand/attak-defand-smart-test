struct ChainRouteStats {
    uint256 total;
    uint256 failed;
}

mapping(uint256 => ChainRouteStats) public chainRoutes;

function logChainRoute(uint256 chainId, bool success) external {
    ChainRouteStats storage s = chainRoutes[chainId];
    s.total++;
    if (!success) s.failed++;
}
