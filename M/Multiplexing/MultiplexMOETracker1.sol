function selectorHeatMap(bytes4[] calldata selectors)
    external
    view
    returns (uint256[] memory failureRates)
{
    failureRates = new uint256[](selectors.length);
    for (uint256 i = 0; i < selectors.length; i++) {
        SubcallStats memory s = stats[selectors[i]];
        if (s.calls == 0) {
            failureRates[i] = 0;
        } else {
            failureRates[i] = (s.failures * 1e4) / s.calls; // in basis points
        }
    }
}
