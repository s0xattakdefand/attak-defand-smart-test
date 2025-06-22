contract TapEntropyTracker {
    mapping(bytes4 => uint256) public selectorHits;
    mapping(bytes4 => uint256) public failCount;

    function log(bytes4 sel, bool ok) external {
        selectorHits[sel]++;
        if (!ok) failCount[sel]++;
    }

    function entropy(bytes4 sel) external view returns (uint256) {
        if (selectorHits[sel] == 0) return 0;
        return (failCount[sel] * 1e4) / selectorHits[sel]; // basis points
    }
}
