contract AuctionRace {
    address public highestBidder;
    uint256 public highestBid;

    event NewHighBid(address bidder, uint256 bid);

    function bid() external payable {
        require(msg.value > highestBid, "Not highest");
        highestBidder = msg.sender;
        highestBid = msg.value;
        emit NewHighBid(msg.sender, msg.value);
    }

    function winner() external view returns (address) {
        return highestBidder;
    }
}
