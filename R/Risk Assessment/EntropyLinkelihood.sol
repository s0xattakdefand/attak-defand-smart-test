contract EntropyLikelihood {
    mapping(bytes4 => uint8) public entropy;

    function set(bytes4 sel, uint8 score) external {
        entropy[sel] = score;
    }

    function likelihood(bytes4 sel) external view returns (uint256) {
        return entropy[sel] * 10;
    }
}
