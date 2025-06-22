// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ElectionAccessControlMonitoringAttackDefense - Attack and Defense Simulation for Election Access Control and Monitoring in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Election Management (Weak Access Control, No Monitoring)
contract InsecureElectionAccess {
    address public admin;
    mapping(string => uint256) public votes;

    event VoteCast(address indexed voter, string candidate);

    constructor() {
        admin = msg.sender;
    }

    function castVote(string calldata candidate) external {
        // 🔥 No voter registry, no role separation!
        votes[candidate]++;
        emit VoteCast(msg.sender, candidate);
    }

    function adminTweakVote(string calldata candidate, uint256 newCount) external {
        require(msg.sender == admin, "Only admin");
        // 🔥 No logging of admin actions!
        votes[candidate] = newCount;
    }
}

/// @notice Secure Election Management with Full Role-Based Access Control and Monitoring
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureElectionAccess is AccessControl {
    bytes32 public constant VOTER_ROLE = keccak256("VOTER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    mapping(string => uint256) public votes;
    uint256 public electionId;

    event VoteCast(address indexed voter, string candidate, uint256 timestamp);
    event VoteAdjusted(address indexed admin, string candidate, uint256 oldCount, uint256 newCount, uint256 timestamp);

    constructor(uint256 _electionId) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        electionId = _electionId;
    }

    function registerVoter(address voter) external onlyRole(ADMIN_ROLE) {
        _grantRole(VOTER_ROLE, voter);
    }

    function castVote(string calldata candidate) external onlyRole(VOTER_ROLE) {
        votes[candidate]++;
        emit VoteCast(msg.sender, candidate, block.timestamp);
    }

    function adjustVote(string calldata candidate, uint256 newCount) external onlyRole(ADMIN_ROLE) {
        uint256 oldCount = votes[candidate];
        votes[candidate] = newCount;
        emit VoteAdjusted(msg.sender, candidate, oldCount, newCount, block.timestamp);
    }

    function auditVote(string calldata candidate) external view onlyRole(AUDITOR_ROLE) returns (uint256) {
        return votes[candidate];
    }
}

/// @notice Attack contract trying to mutate votes without permission
contract ElectionAccessIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function unauthorizedAdjustVote(string calldata candidate, uint256 newCount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("adminTweakVote(string,uint256)", candidate, newCount)
        );
    }
}
