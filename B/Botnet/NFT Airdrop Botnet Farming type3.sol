contract NFTAirdrop {
    mapping(address => bool) public claimed;
    uint256 public tokenId;

    function claim() public {
        require(!claimed[msg.sender], "Already claimed");
        claimed[msg.sender] = true;
        // mint NFT to msg.sender (omitted for brevity)
        tokenId++;
    }
}
