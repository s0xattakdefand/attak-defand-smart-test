contract GasLeakOracle {
    function branchTest(uint256 value) external pure returns (uint256) {
        if (value % 2 == 0) {
            return value * 2; // cheaper
        } else {
            for (uint i = 0; i < 10; i++) {
                value += i;  // heavier gas path
            }
        }
        return value;
    }
}
