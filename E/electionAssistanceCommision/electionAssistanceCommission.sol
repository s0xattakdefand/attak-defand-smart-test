// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ElectionAssistanceAttackDefense - Attack and Defense Simulation for Election Assistance Commission Principles in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Election Management (No Voter Validation, No Replay Protection)
contract InsecureElection {
    mapping(address => bool) public hasVoted;
    mapping(string => uint256) public votes;

    event VoteCast(address indexed voter, string candidate);

    function vote(string calldata candidate) external {
        // 🔥 Anyone can vote, multiple times!
        votes[candidate]++;
        hasVoted[msg.sender] = true;
        emit VoteCast(msg.sender, candidate);
    }
}

/// @notice Secure Election Management with Voter Registry, Ballot Verification, and Replay Protection
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureElection is Ownable {
    using ECDSA for bytes32;

    mapping(address => bool) public registeredVoters;
    mapping(bytes32 => bool) public usedBallots;
    mapping(string => uint256) public votes;

    uint256 public electionId;
    bool public electionActive;

    event VoterRegistered(address indexed voter);
    event VoteCommitted(address indexed voter, string candidate, bytes32 ballotHash);

    constructor(uint256 _electionId) {
        electionId = _electionId;
        electionActive = true;
    }

    function registerVoter(address voter) external onlyOwner {
        registeredVoters[voter] = true;
        emit VoterRegistered(voter);
    }

    function commitVote(
        string calldata candidate,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(electionActive, "Election not active");
        require(registeredVoters[msg.sender], "Not registered");

        bytes32 ballotHash = keccak256(abi.encodePacked(msg.sender, candidate, nonce, electionId, address(this), block.chainid));
        require(!usedBallots[ballotHash], "Ballot already used");

        address signer = ballotHash.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signature");

        usedBallots[ballotHash] = true;
        votes[candidate]++;
        emit VoteCommitted(msg.sender, candidate, ballotHash);
    }

    function endElection() external onlyOwner {
        electionActive = false;
    }
}

/// @notice Attack contract trying to inject fake ballots
contract ElectionIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function stuffBallotBox(string calldata candidate) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("vote(string)", candidate)
        );
    }
}
