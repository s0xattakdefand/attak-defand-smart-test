contract OraclePartitionSimulator {
    mapping(uint256 => int256) public chainPrice;

    function report(uint256 chainId, int256 price) external {
        chainPrice[chainId] = price;
    }

    function isPartitioned(uint256 id1, uint256 id2) external view returns (bool) {
        return absDiff(chainPrice[id1], chainPrice[id2]) > 10;
    }

    function absDiff(int256 a, int256 b) internal pure returns (uint256) {
        return a > b ? uint256(a - b) : uint256(b - a);
    }
}
