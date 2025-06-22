// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LiquidityGovernanceProtectionAttackDefense - Full Attack and Defense Simulation for Protecting Liquidity and Governance in Web3 Smart Contracts
/// @author ChatGPT

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @notice Secure vault protected by governance + multisig escrow
contract SecureLiquidityGovernance {
    address public treasury;
    address public multisigEscrow;
    address public owner;
    uint256 public constant unlockDelay = 3 days;
    uint256 public proposalCounter;

    struct Proposal {
        address to;
        uint256 amount;
        uint256 createdAt;
        bool approved;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;

    event ProposalCreated(uint256 indexed id, address indexed to, uint256 amount);
    event ProposalApproved(uint256 indexed id);
    event ProposalExecuted(uint256 indexed id);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyMultisig() {
        require(msg.sender == multisigEscrow, "Not multisig");
        _;
    }

    constructor(address _treasury, address _multisigEscrow) {
        treasury = _treasury;
        multisigEscrow = _multisigEscrow;
        owner = msg.sender;
    }

    function createLiquidityProposal(address to, uint256 amount) external onlyOwner returns (uint256) {
        proposalCounter++;
        proposals[proposalCounter] = Proposal({
            to: to,
            amount: amount,
            createdAt: block.timestamp,
            approved: false,
            executed: false
        });

        emit ProposalCreated(proposalCounter, to, amount);
        return proposalCounter;
    }

    function approveLiquidityProposal(uint256 proposalId) external onlyMultisig {
        Proposal storage prop = proposals[proposalId];
        require(!prop.approved, "Already approved");
        prop.approved = true;
        emit ProposalApproved(proposalId);
    }

    function executeLiquidityProposal(uint256 proposalId) external {
        Proposal storage prop = proposals[proposalId];
        require(prop.approved, "Not approved by multisig");
        require(!prop.executed, "Already executed");
        require(block.timestamp >= prop.createdAt + unlockDelay, "Unlock delay not passed");

        IERC20(treasury).transfer(prop.to, prop.amount);

        prop.executed = true;
        emit ProposalExecuted(proposalId);
    }
}

/// @notice Attack contract trying to drain liquidity without multisig approval
contract LiquidityAttackIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryDirectExecute(uint256 proposalId) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("executeLiquidityProposal(uint256)", proposalId)
        );
    }
}
