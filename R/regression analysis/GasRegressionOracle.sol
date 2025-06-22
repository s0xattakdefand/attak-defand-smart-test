contract GasRegressionOracle {
    mapping(bytes4 => uint256) public gasUsed;
    mapping(bytes4 => uint8) public entropy;

    event Logged(bytes4 selector, uint256 gas);

    function log(bytes4 selector, uint256 gas, uint8 entropyScore) external {
        gasUsed[selector] = gas;
        entropy[selector] = entropyScore;
        emit Logged(selector, gas);
    }

    function get(bytes4 selector) external view returns (uint256 gas, uint8 e) {
        return (gasUsed[selector], entropy[selector]);
    }
}
