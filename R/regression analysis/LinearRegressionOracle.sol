contract LinearRegressionOracle {
    uint256 public sumX;
    uint256 public sumY;
    uint256 public sumXY;
    uint256 public sumX2;
    uint256 public count;

    function log(uint8 entropy, uint8 success) external {
        sumX += entropy;
        sumY += success;
        sumXY += entropy * success;
        sumX2 += entropy * entropy;
        count++;
    }

    function predict(uint8 entropy) external view returns (int256 y) {
        if (count < 2) return 0;
        int256 n = int256(count);
        int256 a = (int256(n * sumXY) - int256(sumX * sumY)) * 1e18 / (int256(n * sumX2) - int256(sumX * sumX));
        int256 b = (int256(sumY) * 1e18 - a * int256(sumX)) / int256(n);
        return (a * int256(entropy) + b) / 1e18;
    }
}
