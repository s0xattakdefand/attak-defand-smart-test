contract TapEntropyTracker {
    mapping(bytes4 => uint256) public hits;
    mapping(bytes4 => uint256) public fails;

    event DriftLog(bytes4 indexed selector, bool success);

    function log(bytes4 sel, bool ok) external {
        hits[sel]++;
        if (!ok) fails[sel]++;
        emit DriftLog(sel, ok);
    }

    function driftScore(bytes4 sel) external view returns (uint256) {
        if (hits[sel] == 0) return 0;
        return (fails[sel] * 1e4) / hits[sel]; // Failure rate in basis points
    }
}
