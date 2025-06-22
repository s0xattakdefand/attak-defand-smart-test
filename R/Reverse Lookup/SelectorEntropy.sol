contract SelectorEntropyMap {
    struct Stat {
        uint8 entropy;
        uint256 drift;
    }

    mapping(bytes4 => Stat) public profile;

    function register(bytes4 sel, uint8 entropy, uint256 drift) external {
        profile[sel] = Stat(entropy, drift);
    }

    function score(bytes4 sel) external view returns (uint256) {
        Stat memory s = profile[sel];
        return uint256(s.entropy) * (s.drift + 1);
    }
}
