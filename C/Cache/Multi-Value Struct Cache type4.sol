contract MultiCache {
    struct Cached {
        uint256 value;
        uint256 updatedAt;
    }

    mapping(address => Cached) public userCache;

    function cacheForUser(uint256 value) public {
        userCache[msg.sender] = Cached(value, block.timestamp);
    }

    function getCache(address user) public view returns (uint256, uint256) {
        Cached memory c = userCache[user];
        return (c.value, c.updatedAt);
    }
}
