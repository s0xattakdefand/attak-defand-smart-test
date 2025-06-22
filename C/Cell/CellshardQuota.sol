contract CellShardQuota {
    uint256 public callsInThisShard;
    uint256 public shardLimit = 100;

    function doActionInShard() public {
        require(callsInThisShard < shardLimit, "Shard cell limit reached");
        callsInThisShard++;
        // proceed
    }

    function resetShard() public {
        callsInThisShard = 0;
    }
}
