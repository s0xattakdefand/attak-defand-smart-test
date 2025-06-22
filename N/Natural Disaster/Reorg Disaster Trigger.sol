contract ReorgMonitor {
    mapping(uint256 => bytes32) public blockHashes;

    function reportBlock(uint256 blockNum, bytes32 hash) external {
        blockHashes[blockNum] = hash;
    }

    function detectReorg(uint256 blockNum, bytes32 newHash) external view returns (bool) {
        return blockHashes[blockNum] != 0 && blockHashes[blockNum] != newHash;
    }
}
