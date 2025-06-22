contract MultiOracleValidator {
    uint256 public trustedPrice;

    function validate(uint256 price1, uint256 price2) external {
        require(absDiff(price1, price2) <= 3, "Inconsistent data");
        trustedPrice = (price1 + price2) / 2;
    }

    function absDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a - b : b - a;
    }
}
