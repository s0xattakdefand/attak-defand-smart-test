// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Voting {
    // Structure to store candidate information
    struct Candidate {
        string name;
        uint256 voteCount;
    }

    // Mapping to store candidates by ID
    mapping(uint256 => Candidate) public candidates;
    // Mapping to track if an address has voted
    mapping(address => bool) public hasVoted;
    // Total number of candidates
    uint256 public candidateCount;

    // Event to log a vote
    event VoteCast(address indexed voter, uint256 candidateId);

    // Constructor to initialize candidates
    constructor(string[] memory candidateNames) {
        for (uint256 i = 0; i < candidateNames.length; i++) {
            candidateCount++;
            candidates[candidateCount] = Candidate(candidateNames[i], 0);
        }
    }

    // Function to cast a vote
    function vote(uint256 _candidateId) public {
        require(_candidateId > 0 && _candidateId <= candidateCount, "Invalid candidate ID");
        require(!hasVoted[msg.sender], "You have already voted");

        hasVoted[msg.sender] = true;
        candidates[_candidateId].voteCount++;
        emit VoteCast(msg.sender, _candidateId);
    }

    // Function to get a candidate's details
    function getCandidate(uint256 _candidateId) public view returns (string memory name, uint256 voteCount) {
        require(_candidateId > 0 && _candidateId <= candidateCount, "Invalid candidate ID");
        Candidate memory candidate = candidates[_candidateId];
        return (candidate.name, candidate.voteCount);
    }

    // Function to get total candidates
    function getCandidateCount() public view returns (uint256) {
        return candidateCount;
    }
}