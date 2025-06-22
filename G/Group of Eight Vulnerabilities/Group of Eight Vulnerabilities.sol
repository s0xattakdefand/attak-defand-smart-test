// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GroupOfEightAttackDefense - Full Attack and Defense Simulation for G8 in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure G8 Council Control (Vulnerable to Collusion and Abuse)
contract InsecureGroupOfEight {
    address[8] public council;
    mapping(address => bool) public isCouncil;

    event CriticalActionExecuted(address indexed by, string action);

    constructor(address[8] memory initialCouncil) {
        council = initialCouncil;
        for (uint8 i = 0; i < 8; i++) {
            isCouncil[initialCouncil[i]] = true;
        }
    }

    function emergencyAction(string memory action) external {
        require(isCouncil[msg.sender], "Not a council member");
        emit CriticalActionExecuted(msg.sender, action);
        // BAD: Single council member can trigger critical actions
    }
}

/// @notice Secure G8 Council with Threshold Voting (Multisig-Style Defense)
contract SecureGroupOfEight {
    address[8] public council;
    mapping(address => bool) public isCouncil;
    mapping(bytes32 => uint8) public approvals;
    uint8 public constant MIN_APPROVALS = 6; // 6 of 8 required

    event CriticalProposalCreated(bytes32 indexed proposalId, string action);
    event CriticalProposalApproved(address indexed approver, bytes32 indexed proposalId);
    event CriticalActionExecuted(string action);

    constructor(address[8] memory initialCouncil) {
        council = initialCouncil;
        for (uint8 i = 0; i < 8; i++) {
            isCouncil[initialCouncil[i]] = true;
        }
    }

    function createProposal(string memory action) external view returns (bytes32) {
        require(isCouncil[msg.sender], "Not a council member");
        return keccak256(abi.encodePacked(action));
    }

    function approveProposal(bytes32 proposalId) external {
        require(isCouncil[msg.sender], "Not a council member");
        approvals[proposalId]++;
        emit CriticalProposalApproved(msg.sender, proposalId);
    }

    function executeProposal(bytes32 proposalId, string memory action) external {
        require(approvals[proposalId] >= MIN_APPROVALS, "Not enough approvals");
        emit CriticalActionExecuted(action);

        // Reset approvals for future reuse
        approvals[proposalId] = 0;
    }
}

/// @notice Attack contract trying to abuse insecure G8 system
contract GroupOfEightIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function triggerEmergency(string memory fakeAction) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("emergencyAction(string)", fakeAction)
        );
    }
}
