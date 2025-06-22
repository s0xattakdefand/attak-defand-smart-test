contract SafeCache {
    uint256 public cachedPrice;
    uint256 public lastUpdate;
    uint256 public ttl = 10 minutes; // cache expires

    event PriceUpdated(uint256 price, uint256 timestamp);

    function updatePrice(uint256 price) public {
        require(price > 0, "Invalid");
        cachedPrice = price;
        lastUpdate = block.timestamp;
        emit PriceUpdated(price, block.timestamp);
    }

    function getPrice() public view returns (uint256) {
        require(block.timestamp <= lastUpdate + ttl, "Cache expired");
        return cachedPrice;
    }
}
