contract OracleAggregator {
    uint256 public lastPrice;

    function updatePrice(uint256 price1, uint256 price2) external {
        require(absDiff(price1, price2) <= 5, "Divergent feeds");
        lastPrice = (price1 + price2) / 2;
    }

    function absDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a - b : b - a;
    }
}
