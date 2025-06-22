mapping(bytes4 => uint256) public selectorCounts;

function trackSelector(bytes4 selector) external {
    selectorCounts[selector]++;
}

function getSelectorEntropy(bytes4 selector, uint256 total) external view returns (uint256) {
    uint256 count = selectorCounts[selector];
    if (count == 0 || total == 0) return 0;
    uint256 ratio = (count * 1e18) / total;
    return (ratio * log2(ratio)) / 1e18;
}

function log2(uint256 x) internal pure returns (uint256) {
    return x > 0 ? logBase(x, 2) : 0;
}

function logBase(uint256 x, uint256 base) internal pure returns (uint256) {
    uint256 result = 0;
    while (x >= base) {
        result++;
        x /= base;
    }
    return result * 1e18;
}
