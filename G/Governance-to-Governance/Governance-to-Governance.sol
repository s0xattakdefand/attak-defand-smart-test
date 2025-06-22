// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GovernanceToGovernanceAttackDefense - Full Attack and Defense Simulation for G2G Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Governance-to-Governance Relay Contract (Vulnerable to Cross-Drift)
contract InsecureG2GRelay {
    address public sourceGovernance;
    address public targetGovernance;

    event CrossProposalRelayed(address indexed from, address indexed to, string proposalData);

    constructor(address _source, address _target) {
        sourceGovernance = _source;
        targetGovernance = _target;
    }

    function relayProposal(string memory proposalData) external {
        // BAD: Any sender can relay a proposal
        emit CrossProposalRelayed(sourceGovernance, targetGovernance, proposalData);
    }
}

/// @notice Secure G2G Relay Contract (Whitelisted Governance Only + Non-Replayable)
contract SecureG2GRelay {
    address public immutable sourceGovernance;
    address public immutable targetGovernance;
    uint256 public immutable deploymentBlock;
    mapping(bytes32 => bool) public usedProposalHashes;

    event SecureCrossProposalRelayed(address indexed from, address indexed to, string proposalData);

    constructor(address _source, address _target) {
        sourceGovernance = _source;
        targetGovernance = _target;
        deploymentBlock = block.number;
    }

    function relayProposal(string memory proposalData) external {
        require(msg.sender == sourceGovernance, "Only source governance can relay");

        bytes32 proposalHash = keccak256(abi.encodePacked(proposalData, block.chainid, address(this)));

        require(!usedProposalHashes[proposalHash], "Proposal already relayed");
        usedProposalHashes[proposalHash] = true;

        require(block.number >= deploymentBlock, "Invalid proposal block timing");

        emit SecureCrossProposalRelayed(sourceGovernance, targetGovernance, proposalData);
    }
}

/// @notice Attack contract simulating fake cross-governance relay
contract G2GIntruder {
    address public targetInsecureG2G;

    constructor(address _targetInsecureG2G) {
        targetInsecureG2G = _targetInsecureG2G;
    }

    function injectFakeProposal(string memory maliciousProposal) external returns (bool success) {
        (success, ) = targetInsecureG2G.call(
            abi.encodeWithSignature("relayProposal(string)", maliciousProposal)
        );
    }
}
