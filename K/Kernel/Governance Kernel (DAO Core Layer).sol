pragma solidity ^0.8.21;

contract GovernanceKernel {
    struct Proposal {
        string description;
        uint256 voteCount;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalId;

    function propose(string memory description) external {
        proposals[proposalId++] = Proposal(description, 0, false);
    }

    function vote(uint256 id) external {
        proposals[id].voteCount++;
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(!p.executed && p.voteCount >= 3, "Not ready");
        p.executed = true;
        // Execute action here
    }
}
