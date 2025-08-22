// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Decentralized Market Auction (DMA) smart contract
contract DMA {
    // Struct to represent an auction
    struct Auction {
        address auctioneer; // Creator of the auction
        string asset; // Description or identifier of the asset (e.g., NFT ID, token name)
        uint256 highestBid; // Current highest bid in wei
        address highestBidder; // Address of the highest bidder
        uint256 endTime; // Timestamp when auction ends
        bool ended; // Whether the auction has ended
        mapping(address => uint256) bids; // Bids placed by each address
    }

    // Mapping to store auctions by ID
    mapping(bytes32 => Auction) public auctions;

    // Owner of the contract
    address public owner;

    // Event emitted when an auction is created
    event AuctionCreated(bytes32 indexed auctionId, address auctioneer, string asset, uint256 endTime);

    // Event emitted when a bid is placed
    event BidPlaced(bytes32 indexed auctionId, address bidder, uint256 amount);

    // Event emitted when an auction ends
    event AuctionEnded(bytes32 indexed auctionId, address winner, uint256 amount);

    // Event emitted when funds are refunded
    event Refunded(bytes32 indexed auctionId, address bidder, uint256 amount);

    // Modifier to restrict actions to the owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to check if auction exists and is active
    modifier onlyActiveAuction(bytes32 auctionId) {
        require(auctions[auctionId].auctioneer != address(0), "Auction does not exist");
        require(!auctions[auctionId].ended, "Auction already ended");
        require(block.timestamp <= auctions[auctionId].endTime, "Auction has expired");
        _;
    }

    // Constructor to initialize the owner
    constructor() {
        owner = msg.sender;
    }

    // Create a new auction
    function createAuction(string memory asset, uint256 duration) 
        external 
        returns (bytes32) 
    {
        require(bytes(asset).length > 0, "Asset description required");
        require(duration > 0, "Duration must be greater than 0");

        bytes32 auctionId = keccak256(abi.encodePacked(msg.sender, asset, block.timestamp));
        Auction storage auction = auctions[auctionId];
        require(auction.auctioneer == address(0), "Auction ID already exists");

        auction.auctioneer = msg.sender;
        auction.asset = asset;
        auction.highestBid = 0;
        auction.highestBidder = address(0);
        auction.endTime = block.timestamp + duration;
        auction.ended = false;

        emit AuctionCreated(auctionId, msg.sender, asset, auction.endTime);
        return auctionId;
    }

    // Place a bid on an auction
    function placeBid(bytes32 auctionId) 
        external 
        payable 
        onlyActiveAuction(auctionId) 
    {
        require(msg.value > auctions[auctionId].highestBid, "Bid must exceed current highest bid");
        require(msg.sender != auctions[auctionId].auctioneer, "Auctioneer cannot bid");

        // Refund the previous highest bidder
        if (auctions[auctionId].highestBidder != address(0)) {
            uint256 refundAmount = auctions[auctionId].bids[auctions[auctionId].highestBidder];
            payable(auctions[auctionId].highestBidder).transfer(refundAmount);
            emit Refunded(auctionId, auctions[auctionId].highestBidder, refundAmount);
        }

        // Record the new bid
        auctions[auctionId].bids[msg.sender] = msg.value;
        auctions[auctionId].highestBid = msg.value;
        auctions[auctionId].highestBidder = msg.sender;

        emit BidPlaced(auctionId, msg.sender, msg.value);
    }

    // End an auction and transfer funds to the auctioneer
    function endAuction(bytes32 auctionId) 
        external 
    {
        Auction storage auction = auctions[auctionId];
        require(auction.auctioneer != address(0), "Auction does not exist");
        require(!auction.ended, "Auction already ended");
        require(block.timestamp > auction.endTime, "Auction not yet ended");
        require(msg.sender == auction.auctioneer || msg.sender == owner, "Only auctioneer or owner can end");

        auction.ended = true;

        if (auction.highestBidder != address(0)) {
            // Transfer highest bid to auctioneer
            payable(auction.auctioneer).transfer(auction.highestBid);
            emit AuctionEnded(auctionId, auction.highestBidder, auction.highestBid);
        } else {
            // No bids, just mark as ended
            emit AuctionEnded(auctionId, address(0), 0);
        }
    }

    // Withdraw bid if auction is still active and bidder wants to cancel
    function withdrawBid(bytes32 auctionId) 
        external 
        onlyActiveAuction(auctionId) 
    {
        Auction storage auction = auctions[auctionId];
        uint256 bidAmount = auction.bids[msg.sender];
        require(bidAmount > 0, "No bid to withdraw");
        require(msg.sender != auction.highestBidder, "Highest bidder cannot withdraw");

        // Clear the bid
        auction.bids[msg.sender] = 0;
        
        // Refund the bidder
        payable(msg.sender).transfer(bidAmount);
        emit Refunded(auctionId, msg.sender, bidAmount);
    }

    // Get auction details
    function getAuctionDetails(bytes32 auctionId) 
        external 
        view 
        returns (address, string memory, uint256, address, uint256, bool) 
    {
        Auction storage auction = auctions[auctionId];
        return (
            auction.auctioneer,
            auction.asset,
            auction.highestBid,
            auction.highestBidder,
            auction.endTime,
            auction.ended
        );
    }

    // Get bid amount for a specific bidder
    function getBid(bytes32 auctionId, address bidder) 
        external 
        view 
        returns (uint256) 
    {
        return auctions[auctionId].bids[bidder];
    }

    // Emergency withdraw by owner (in case funds are stuck)
    function emergencyWithdraw() external onlyOwner {
        uint256 amount = address(this).balance;
        require(amount > 0, "No funds to withdraw");
        payable(owner).transfer(amount);
    }

    // Prevent accidental ETH deposits
    receive() external payable {
        revert("Use placeBid to send ETH");
    }
}