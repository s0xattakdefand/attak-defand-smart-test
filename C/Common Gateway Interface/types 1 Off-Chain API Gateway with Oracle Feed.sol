interface IOracle {
    function fetchData() external view returns (bytes32);
}

contract OracleGateway {
    IOracle public oracle;

    constructor(address oracleAddr) {
        oracle = IOracle(oracleAddr);
    }

    function getOracleValue() external view returns (bytes32) {
        // Acts as an on-chain gateway
        return oracle.fetchData();
    }
}
