contract SpamBotGovernance {
    uint256 public proposalCount;

    function propose(string memory proposal) public {
        proposalCount++;
        // spam prevention omitted
    }
}
