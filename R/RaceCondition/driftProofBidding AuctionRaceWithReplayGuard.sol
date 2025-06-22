import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract AuctionRaceWithReplayGuard {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedHashes;
    address public highestBidder;
    uint256 public highestBid;

    event BidPlaced(address bidder, uint256 bid);

    function bid(
        uint256 amount,
        bytes calldata sig
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, amount));
        require(!usedHashes[hash], "Replay detected");
        require(hash.toEthSignedMessageHash().recover(sig) == msg.sender, "Invalid sig");

        usedHashes[hash] = true;
        require(amount > highestBid, "Not high enough");
        highestBidder = msg.sender;
        highestBid = amount;
        emit BidPlaced(msg.sender, amount);
    }
}
