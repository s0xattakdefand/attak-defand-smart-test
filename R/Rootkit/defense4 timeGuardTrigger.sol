contract TimeGate {
    function checkTime(uint256 ts) public view returns (bool) {
        require(block.timestamp <= ts + 7 days, "Expired logic trigger");
        return true;
    }
}
