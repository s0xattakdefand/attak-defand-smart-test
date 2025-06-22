// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CCBConfigGovernor {
    struct Proposal {
        string key;
        bytes32 value;
        uint256 votesFor;
        uint256 votesAgainst;
        uint256 deadline;
        bool executed;
        bool approved;
    }

    address[] public ccbMembers;
    uint256 public constant VOTE_DELAY = 15; // blocks
    uint256 public constant VOTE_THRESHOLD = 2;

    mapping(uint256 => Proposal) public proposals;
    mapping(address => bool) public isCCBMember;
    uint256 public proposalCount;

    event ProposalCreated(uint256 id, string key, bytes32 value);
    event VoteCast(uint256 id, address voter, bool approve);
    event ProposalExecuted(uint256 id, bool approved);

    modifier onlyCCB() {
        require(isCCBMember[msg.sender], "Not a CCB member");
        _;
    }

    constructor(address[] memory members) {
        for (uint256 i = 0; i < members.length; i++) {
            ccbMembers.push(members[i]);
            isCCBMember[members[i]] = true;
        }
    }

    function propose(string calldata key, bytes32 value) external onlyCCB returns (uint256 id) {
        id = proposalCount++;
        proposals[id] = Proposal({
            key: key,
            value: value,
            votesFor: 0,
            votesAgainst: 0,
            deadline: block.number + VOTE_DELAY,
            executed: false,
            approved: false
        });
        emit ProposalCreated(id, key, value);
    }

    function vote(uint256 id, bool approve) external onlyCCB {
        Proposal storage p = proposals[id];
        require(block.number <= p.deadline, "Voting closed");

        if (approve) {
            p.votesFor++;
        } else {
            p.votesAgainst++;
        }

        emit VoteCast(id, msg.sender, approve);
    }

    function execute(uint256 id) external onlyCCB {
        Proposal storage p = proposals[id];
        require(!p.executed, "Already executed");
        require(block.number > p.deadline, "Vote still ongoing");

        p.executed = true;
        p.approved = (p.votesFor >= VOTE_THRESHOLD);
        emit ProposalExecuted(id, p.approved);

        // Integration point: pass result to `ConfigurationControlManager` or relay
    }

    function getCCBMembers() external view returns (address[] memory) {
        return ccbMembers;
    }
}
