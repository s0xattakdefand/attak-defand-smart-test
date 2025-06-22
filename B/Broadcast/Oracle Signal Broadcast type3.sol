contract OracleBroadcaster {
    event OracleSignal(string asset, uint256 requestId, address indexed caller);

    function triggerOracle(string calldata asset, uint256 requestId) public {
        emit OracleSignal(asset, requestId, msg.sender);
    }
}
