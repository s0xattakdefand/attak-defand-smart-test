mapping(address => uint256) public lastProposal;
uint256 public cooldown = 1 days;

function propose(bytes calldata proposal) external {
    require(block.timestamp > lastProposal[msg.sender] + cooldown, "Wait cooldown");
    lastProposal[msg.sender] = block.timestamp;
    // Store proposal
}
