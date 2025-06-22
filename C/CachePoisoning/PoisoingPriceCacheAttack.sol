contract PoisonedPriceCache {
    uint256 public price;
    uint256 public updatedAt;

    function setPrice(uint256 fakePrice) external {
        price = fakePrice;  // ❌ no validation
        updatedAt = block.timestamp;
    }

    function getPrice() external view returns (uint256) {
        return price;
    }
}
