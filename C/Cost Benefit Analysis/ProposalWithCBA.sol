// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ProposalWithCBA {
    struct Proposal {
        string description;
        uint256 benefitScore;
        uint256 costScore;
        bool executed;
    }

    Proposal[] public proposals;

    function submit(string calldata desc, uint256 benefit, uint256 cost) external {
        proposals.push(Proposal(desc, benefit, cost, false));
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(!p.executed, "Already done");
        require(p.benefitScore > p.costScore, "CBA: Net negative");

        p.executed = true;
    }

    function evaluate(uint256 id) external view returns (string memory status) {
        Proposal memory p = proposals[id];
        if (p.benefitScore > p.costScore) return "✅ Worth executing";
        else return "❌ Not worth it";
    }
}
