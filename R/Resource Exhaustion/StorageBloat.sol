contract StorageBloat {
    uint256[] public blob;
    uint256 public constant MAX = 500;

    function writeMany(uint256 count) external {
        require(blob.length + count <= MAX, "Limit exceeded");
        for (uint256 i = 0; i < count; ++i) {
            blob.push(block.timestamp);
        }
    }
}
