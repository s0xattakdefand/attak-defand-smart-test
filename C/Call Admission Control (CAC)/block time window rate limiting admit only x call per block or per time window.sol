contract BlockWindowLimit {
    uint256 public callsThisBlock;
    uint256 public lastBlock;
    uint256 public blockCap = 5; // only 5 calls admitted per block

    function limitedAction() external {
        if (block.number != lastBlock) {
            lastBlock = block.number;
            callsThisBlock = 0;
        }
        require(callsThisBlock < blockCap, "[CAC] Block call limit reached");
        callsThisBlock++;
        // proceed
    }
}
