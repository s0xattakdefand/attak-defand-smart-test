// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title Developers Alliance for Standards Harmonization (DASH)
 * @notice
 *   A governance contract where registered member developers propose,
 *   vote on, and adopt technical standards in a collaborative alliance.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can add/remove members and pause/unpause the contract.
 *   • MEMBER_ROLE: may propose new standards and vote on proposals.
 *
 * Proposal Lifecycle:
 *   1. Member calls `proposeStandard(name, description)` → returns `proposalId`.
 *   2. Voting opens immediately and lasts `VOTING_DURATION` seconds.
 *   3. Members call `vote(proposalId, support)` once per proposal.
 *   4. After voting ends, anyone calls `executeProposal(proposalId)` to finalize:
 *        - If forVotes > againstVotes and quorum reached, standard is adopted.
 *        - Otherwise, proposal fails.
 *
 * Standards once adopted remain in the registry.
 */
contract DevelopersAlliance is AccessControl, Pausable {
    bytes32 public constant MEMBER_ROLE    = keccak256("MEMBER_ROLE");
    uint256 public constant VOTING_DURATION = 3 days;
    uint256 public constant QUORUM          = 3;  // minimum total votes required

    struct Proposal {
        string  name;
        string  description;
        address proposer;
        uint256 startTime;
        uint256 forVotes;
        uint256 againstVotes;
        bool    executed;
        bool    adopted;
    }

    Proposal[] public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    string[] public adoptedStandards;

    event MemberAdded(address indexed account);
    event MemberRemoved(address indexed account);
    event StandardProposed(uint256 indexed proposalId, address indexed proposer, string name);
    event VoteCast(address indexed voter, uint256 indexed proposalId, bool support);
    event ProposalExecuted(uint256 indexed proposalId, bool adopted);
    event StandardAdopted(uint256 indexed proposalId, string name);

    modifier onlyMember() {
        require(hasRole(MEMBER_ROLE, msg.sender), "DASH: not a member");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MEMBER_ROLE, admin);
    }

    /// @notice Admin adds a new member developer.
    function addMember(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(MEMBER_ROLE, account);
        emit MemberAdded(account);
    }

    /// @notice Admin removes a member developer.
    function removeMember(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(MEMBER_ROLE, account);
        emit MemberRemoved(account);
    }

    /// @notice Member proposes a new standard.
    function proposeStandard(string calldata name, string calldata description)
        external
        whenNotPaused
        onlyMember
        returns (uint256 proposalId)
    {
        proposalId = proposals.length;
        proposals.push(Proposal({
            name:        name,
            description: description,
            proposer:    msg.sender,
            startTime:   block.timestamp,
            forVotes:    0,
            againstVotes:0,
            executed:    false,
            adopted:     false
        }));
        emit StandardProposed(proposalId, msg.sender, name);
    }

    /// @notice Member casts a vote on an active proposal.
    function vote(uint256 proposalId, bool support) external onlyMember {
        require(proposalId < proposals.length, "DASH: invalid proposal");
        Proposal storage p = proposals[proposalId];
        require(block.timestamp <= p.startTime + VOTING_DURATION, "DASH: voting closed");
        require(!hasVoted[proposalId][msg.sender], "DASH: already voted");

        hasVoted[proposalId][msg.sender] = true;
        if (support) {
            p.forVotes += 1;
        } else {
            p.againstVotes += 1;
        }
        emit VoteCast(msg.sender, proposalId, support);
    }

    /// @notice Finalize a proposal after voting ends.
    function executeProposal(uint256 proposalId) external whenNotPaused {
        require(proposalId < proposals.length, "DASH: invalid proposal");
        Proposal storage p = proposals[proposalId];
        require(!p.executed, "DASH: already executed");
        require(block.timestamp > p.startTime + VOTING_DURATION, "DASH: voting not ended");

        p.executed = true;
        uint256 totalVotes = p.forVotes + p.againstVotes;
        if (totalVotes >= QUORUM && p.forVotes > p.againstVotes) {
            p.adopted = true;
            adoptedStandards.push(p.name);
            emit StandardAdopted(proposalId, p.name);
        }
        emit ProposalExecuted(proposalId, p.adopted);
    }

    /// @notice Get the number of proposals created.
    function getProposalCount() external view returns (uint256) {
        return proposals.length;
    }

    /// @notice Retrieve adopted standard names.
    function getAdoptedStandards() external view returns (string[] memory) {
        return adoptedStandards;
    }

    /// @notice Pause proposing and executing.
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause actions.
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
