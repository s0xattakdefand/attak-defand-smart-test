function getLastBlockLatency(address user) external view returns (uint256 latency) {
    AccessEvent[] memory evs = logs[user];
    if (evs.length == 0) return 0;
    AccessEvent memory e = evs[evs.length - 1];
    if (e.blocked) {
        latency = e.blockTime - e.requestTime;
    }
}
