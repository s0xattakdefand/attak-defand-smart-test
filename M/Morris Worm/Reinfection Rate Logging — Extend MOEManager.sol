struct WormMetrics {
    uint256 totalTargets;
    uint256 reinfected;
    mapping(address => bool) seen;
}

mapping(bytes32 => WormMetrics) public wormData;

function logWormSpread(bytes32 wormId, address target) external {
    WormMetrics storage w = wormData[wormId];
    w.totalTargets++;
    if (w.seen[target]) {
        w.reinfected++;
    }
    w.seen[target] = true;
}

function getWormStats(bytes32 wormId) external view returns (uint256 total, uint256 reinfected) {
    WormMetrics storage w = wormData[wormId];
    return (w.totalTargets, w.reinfected);
}
