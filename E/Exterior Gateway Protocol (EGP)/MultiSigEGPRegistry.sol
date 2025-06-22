// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MultiSigEGPRegistry {
    struct Route {
        uint256 asNumber;
        string destination;
        address nextHop;
        uint256 metric;
    }

    Route[] public routes;

    // A simple multi-signature structure: route proposals that need confirmations
    struct RouteProposal {
        Route route;
        uint256 confirmations;
        mapping(address => bool) confirmed;
        bool executed;
    }

    RouteProposal[] public proposals;

    address[] public admins;

    event ProposalCreated(uint256 proposalId, uint256 asNumber, string destination, address nextHop, uint256 metric);
    event ProposalConfirmed(uint256 proposalId, address admin);
    event ProposalExecuted(uint256 proposalId);

    constructor(address[] memory _admins) {
        admins = _admins;
    }

    modifier onlyAdmin() {
        bool found = false;
        for (uint256 i = 0; i < admins.length; i++) {
            if (admins[i] == msg.sender) {
                found = true;
                break;
            }
        }
        require(found, "Not an admin");
        _;
    }

    function proposeRoute(
        uint256 asNumber,
        string calldata destination,
        address nextHop,
        uint256 metric
    ) external onlyAdmin {
        RouteProposal storage proposal = proposals.push();
        proposal.route = Route(asNumber, destination, nextHop, metric);
        proposal.confirmations = 0;
        emit ProposalCreated(proposals.length - 1, asNumber, destination, nextHop, metric);
    }

    function confirmProposal(uint256 proposalId) external onlyAdmin {
        require(proposalId < proposals.length, "Invalid proposalId");
        RouteProposal storage proposal = proposals[proposalId];
        require(!proposal.confirmed[msg.sender], "Already confirmed");
        require(!proposal.executed, "Already executed");
        proposal.confirmed[msg.sender] = true;
        proposal.confirmations++;
        emit ProposalConfirmed(proposalId, msg.sender);
    }

    function executeProposal(uint256 proposalId) external onlyAdmin {
        require(proposalId < proposals.length, "Invalid proposalId");
        RouteProposal storage proposal = proposals[proposalId];
        require(!proposal.executed, "Proposal executed");
        // Require majority (for simplicity, > half of admins)
        require(proposal.confirmations > admins.length / 2, "Not enough confirmations");
        
        routes.push(proposal.route);
        proposal.executed = true;
        emit ProposalExecuted(proposalId);
    }
}
