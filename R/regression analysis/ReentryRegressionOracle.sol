contract ReentryRegressionOracle {
    uint256 public sumDelta;
    uint256 public sumRisk;
    uint256 public count;

    function log(uint256 blockDelta, uint8 riskScore) external {
        sumDelta += blockDelta;
        sumRisk += riskScore;
        count++;
    }

    function avgRisk() external view returns (uint256) {
        return count > 0 ? sumRisk / count : 0;
    }
}
