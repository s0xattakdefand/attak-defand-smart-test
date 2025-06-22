contract ConstantBranch {
    function secureBranch(uint256 value) external pure returns (uint256) {
        uint256 result = value;
        if (value % 2 == 0) {
            result *= 2;
        } else {
            result += 10;
        }

        // Consume same gas (dummy ops)
        for (uint i = 0; i < 5; i++) {
            result += 1;
        }

        return result;
    }
}
