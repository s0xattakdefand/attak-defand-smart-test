contract EntropyReplayOracle {
    mapping(bytes4 => uint8) public entropy;
    mapping(bytes4 => bool) public successful;

    function log(bytes4 selector, uint8 entropyScore, bool success) external {
        entropy[selector] = entropyScore;
        successful[selector] = success;
    }

    function isHighRisk(bytes4 selector) external view returns (bool) {
        return entropy[selector] > 6 && successful[selector];
    }
}
