contract DriftAwareScorer {
    struct SelectorInfo {
        uint256 entropy;
        uint256 score;
        uint256 drift;
    }

    mapping(bytes4 => SelectorInfo) public selectors;

    function log(bytes4 sel, uint8 entropy, bool ok, uint256 drift) external {
        SelectorInfo storage s = selectors[sel];
        s.entropy = entropy;
        s.drift = drift;
        s.score += ok ? (entropy * (drift + 1)) : drift;
    }

    function getScore(bytes4 sel) external view returns (uint256) {
        return selectors[sel].score;
    }
}
