struct InterfaceMetric {
    uint256 calls;
    uint256 failures;
}

mapping(address => InterfaceMetric) public interfaceStats;

function logRoute(address target, bool ok) external {
    InterfaceMetric storage m = interfaceStats[target];
    m.calls++;
    if (!ok) m.failures++;
}
