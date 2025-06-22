contract TapReplayer {
    struct Snapshot {
        address target;
        bytes data;
    }

    Snapshot[] public log;

    function record(address target, bytes calldata data) external {
        log.push(Snapshot(target, data));
    }

    function replayAll() external {
        for (uint256 i = 0; i < log.length; i++) {
            (bool ok, ) = log[i].target.call(log[i].data);
            require(ok, "Replay failed");
        }
    }
}
