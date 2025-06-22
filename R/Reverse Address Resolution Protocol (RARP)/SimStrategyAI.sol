struct SelectorMeta {
    bytes4 selector;
    uint256 drift;
    uint256 score;
    uint8 entropy;
}

mapping(bytes4 => SelectorMeta) public metadata;

function register(bytes4 selector, uint8 entropy, uint256 drift) external {
    metadata[selector] = SelectorMeta(selector, drift, drift * entropy, entropy);
}

function mostVolatile() public view returns (bytes4 best) {
    uint256 max = 0;
    for (uint256 i = 0; i < volatile.length; i++) {
        SelectorMeta memory s = metadata[volatile[i]];
        uint256 val = s.drift * s.entropy;
        if (val > max) {
            max = val;
            best = s.selector;
        }
    }
}
