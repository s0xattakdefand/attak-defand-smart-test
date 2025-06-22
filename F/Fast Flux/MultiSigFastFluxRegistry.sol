// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MultiSigFastFluxRegistry {
    struct Route {
        address node;
    }

    Route[] public fluxNodes;
    uint256 public fluxInterval;

    struct Proposal {
        address node;
        uint256 confirmations;
        mapping(address => bool) confirmed;
        bool executed;
    }

    Proposal[] public proposals;
    address[] public admins;

    event ProposalCreated(uint256 proposalId, address node);
    event ProposalConfirmed(uint256 proposalId, address admin);
    event ProposalExecuted(uint256 proposalId, address node);
    event FluxIntervalUpdated(uint256 newInterval);

    constructor(address[] memory _admins, uint256 _fluxInterval) {
        admins = _admins;
        fluxInterval = _fluxInterval;
    }

    modifier onlyAdmin() {
        bool found;
        for (uint256 i = 0; i < admins.length; i++) {
            if (admins[i] == msg.sender) {
                found = true;
                break;
            }
        }
        require(found, "Not an admin");
        _;
    }

    function proposeNode(address node) external onlyAdmin {
        require(node != address(0), "Invalid node address");
        Proposal storage p = proposals.push();
        p.node = node;
        p.confirmations = 0;
        emit ProposalCreated(proposals.length - 1, node);
    }

    function confirmProposal(uint256 proposalId) external onlyAdmin {
        require(proposalId < proposals.length, "Invalid proposal ID");
        Proposal storage p = proposals[proposalId];
        require(!p.confirmed[msg.sender], "Already confirmed");
        require(!p.executed, "Already executed");
        p.confirmed[msg.sender] = true;
        p.confirmations++;
        emit ProposalConfirmed(proposalId, msg.sender);
    }

    function executeProposal(uint256 proposalId) external onlyAdmin {
        require(proposalId < proposals.length, "Invalid proposal ID");
        Proposal storage p = proposals[proposalId];
        require(!p.executed, "Already executed");
        require(p.confirmations > admins.length / 2, "Not enough confirmations");

        fluxNodes.push(Route(p.node));
        p.executed = true;
        emit ProposalExecuted(proposalId, p.node);
    }

    function updateFluxInterval(uint256 newInterval) external onlyAdmin {
        require(newInterval > 0, "Invalid interval");
        fluxInterval = newInterval;
        emit FluxIntervalUpdated(newInterval);
    }

    function getActiveNode() public view returns (address) {
        require(fluxNodes.length > 0, "No flux nodes available");
        uint256 index = (block.timestamp / fluxInterval) % fluxNodes.length;
        return fluxNodes[index].node;
    }
}
