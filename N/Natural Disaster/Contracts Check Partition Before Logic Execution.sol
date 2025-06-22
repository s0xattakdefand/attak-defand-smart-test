interface IPartitionSet {
    function requireAvailable(PartitionSet.Region region) external view;
}

contract ZKBridgeExecutor {
    IPartitionSet public ps;

    constructor(address _partitionSet) {
        ps = IPartitionSet(_partitionSet);
    }

    function bridgeExecute(bytes calldata data) external {
        ps.requireAvailable(PartitionSet.Region.ZK);
        // process normally
    }
}
