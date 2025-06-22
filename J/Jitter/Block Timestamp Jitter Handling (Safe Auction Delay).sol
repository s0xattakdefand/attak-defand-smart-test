pragma solidity ^0.8.21;

contract AuctionJitterSafe {
    uint256 public startTime;
    uint256 public duration = 1 hours;
    address public highestBidder;
    uint256 public highestBid;

    constructor() {
        startTime = block.timestamp + 5 minutes; // buffer to handle jitter
    }

    function bid() external payable {
        require(block.timestamp >= startTime, "Auction not started");
        require(block.timestamp <= startTime + duration, "Auction ended");
        require(msg.value > highestBid, "Low bid");

        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
