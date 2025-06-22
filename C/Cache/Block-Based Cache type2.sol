contract BlockCache {
    uint256 public value;
    uint256 public expiresAtBlock;

    function update(uint256 newVal, uint256 ttlBlocks) public {
        value = newVal;
        expiresAtBlock = block.number + ttlBlocks;
    }

    function get() public view returns (uint256) {
        require(block.number <= expiresAtBlock, "Cache expired");
        return value;
    }
}
