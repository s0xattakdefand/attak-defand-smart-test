interface IOracle {
    function latestPrice() external view returns (uint256);
}

contract DualOracleValidator {
    IOracle public oracle1;
    IOracle public oracle2;
    uint256 public price;

    constructor(address o1, address o2) {
        oracle1 = IOracle(o1);
        oracle2 = IOracle(o2);
    }

    function updatePrice() external {
        uint256 p1 = oracle1.latestPrice();
        uint256 p2 = oracle2.latestPrice();

        require(_close(p1, p2), "Disagreement in oracles");
        price = (p1 + p2) / 2;
    }

    function _close(uint256 a, uint256 b) internal pure returns (bool) {
        uint256 diff = a > b ? a - b : b - a;
        return diff * 100 / ((a + b) / 2) < 5; // max 5% difference
    }
}
