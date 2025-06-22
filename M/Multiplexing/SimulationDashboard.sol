function getTelemetry(bytes4[] calldata selectors)
    external
    view
    returns (uint256[] memory calls, uint256[] memory fails, uint256[] memory entropy)
{
    uint256 len = selectors.length;
    calls = new uint256[](len);
    fails = new uint256[](len);
    entropy = new uint256[](len);

    for (uint256 i = 0; i < len; i++) {
        (uint256 c, uint256 f) = getStats(selectors[i]);
        calls[i] = c;
        fails[i] = f;
        entropy[i] = selectorCounts[selectors[i]];
    }
}
