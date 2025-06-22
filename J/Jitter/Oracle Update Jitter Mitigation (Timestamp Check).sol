pragma solidity ^0.8.21;

interface IOracle {
    function latestPrice() external view returns (uint256);
    function lastUpdated() external view returns (uint256);
}

contract OracleJitterSafe {
    IOracle public oracle;
    uint256 public maxAge = 60; // seconds

    constructor(address _oracle) {
        oracle = IOracle(_oracle);
    }

    function getPrice() public view returns (uint256) {
        require(block.timestamp - oracle.lastUpdated() <= maxAge, "Stale oracle data");
        return oracle.latestPrice();
    }
}
