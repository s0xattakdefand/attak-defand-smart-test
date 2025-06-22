contract TTLCache {
    uint256 public value;
    uint256 public updatedAt;
    uint256 public ttl = 300;

    function update(uint256 newVal) public {
        value = newVal;
        updatedAt = block.timestamp;
    }

    function get() public view returns (uint256) {
        require(block.timestamp <= updatedAt + ttl, "Expired");
        return value;
    }
}
