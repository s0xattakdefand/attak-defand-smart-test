// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AutonomousSystem {
    address public admin;
    uint256 public rewardRate = 1 ether;

    mapping(address => bool) public voters;
    uint256 public votes;
    uint256 public proposalCount;
    uint256 public lastProposalTime;

    event RewardRateUpdated(uint256 newRate);
    event ProposalInitiated(uint256 proposedRate, uint256 timestamp);

    struct Proposal {
        uint256 proposedRate;
        uint256 approvals;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
        voters[msg.sender] = true; // first voter
    }

    function addVoter(address voter) public onlyAdmin {
        voters[voter] = true;
    }

    function proposeRewardRate(uint256 newRate) public {
        require(voters[msg.sender], "Not a voter");
        proposalCount++;
        proposals[proposalCount] = Proposal(newRate, 1, false);
        lastProposalTime = block.timestamp;
        emit ProposalInitiated(newRate, block.timestamp);
    }

    function approveProposal(uint256 id) public {
        require(voters[msg.sender], "Not a voter");
        Proposal storage p = proposals[id];
        require(!p.executed, "Already executed");

        p.approvals += 1;

        if (p.approvals >= 3) {
            rewardRate = p.proposedRate;
            p.executed = true;
            emit RewardRateUpdated(p.proposedRate);
        }
    }

    function getRewardRate() public view returns (uint256) {
        return rewardRate;
    }
}
