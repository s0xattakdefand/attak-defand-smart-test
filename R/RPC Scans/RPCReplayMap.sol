contract RPCReplayMap {
    struct Entry {
        uint256 timestamp;
        uint256 chainId;
        bytes4 selector;
    }

    Entry[] public log;

    function record(bytes4 selector) external {
        log.push(Entry(block.timestamp, block.chainid, selector));
    }

    function get(uint index) external view returns (Entry memory) {
        return log[index];
    }
}
