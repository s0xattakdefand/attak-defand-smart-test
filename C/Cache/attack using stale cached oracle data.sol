contract StaleCache {
    uint256 public cachedPrice;
    uint256 public lastUpdate;

    function updatePrice(uint256 price) public {
        cachedPrice = price;
        lastUpdate = block.timestamp;
    }

    function trade() public view returns (uint256) {
        return cachedPrice * 2; // ❌ attacker can use stale price
    }
}
