contract MultiMetricRegression {
    struct Record {
        uint8 entropy;
        uint256 gas;
        bool success;
    }

    mapping(bytes4 => Record) public logs;
    event MetricsLogged(bytes4 selector, uint8 entropy, uint256 gas, bool success);

    function log(bytes4 selector, uint8 entropy, uint256 gasUsed, bool success) external {
        logs[selector] = Record(entropy, gasUsed, success);
        emit MetricsLogged(selector, entropy, gasUsed, success);
    }

    function get(bytes4 selector) external view returns (Record memory) {
        return logs[selector];
    }
}
