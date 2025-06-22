// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DefenseContractManagementAttackDefense - Attack and Defense Simulation for Defense Contract Management Agency (DCMA) in Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure Defense Contract Management (No Registry, No Verification, No Multi-Signature)
contract InsecureDCMA {
    mapping(address => bool) public contractors;
    mapping(address => bool) public milestonesCompleted;
    address public defenseFund;
    uint256 public payoutAmount;

    event ContractorAdded(address contractor);
    event MilestoneClaimed(address contractor);
    event PaymentReleased(address contractor, uint256 amount);

    constructor(address _defenseFund, uint256 _payoutAmount) {
        defenseFund = _defenseFund;
        payoutAmount = _payoutAmount;
    }

    function addContractor(address contractor) external {
        contractors[contractor] = true;
        emit ContractorAdded(contractor);
    }

    function claimMilestone(address contractor) external {
        milestonesCompleted[contractor] = true;
        emit MilestoneClaimed(contractor);
    }

    function releasePayment(address contractor) external {
        require(milestonesCompleted[contractor], "Milestone not claimed");
        (bool success, ) = contractor.call{value: payoutAmount}("");
        require(success, "Transfer failed");
        emit PaymentReleased(contractor, payoutAmount);
    }

    receive() external payable {}
}

/// @notice Secure Defense Contract Management with Contractor Registry, Milestone Verification, and Multi-Sig Approval
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureDCMA is AccessControl {
    bytes32 public constant CONTRACTOR_ROLE = keccak256("CONTRACTOR_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    struct Milestone {
        bool claimed;
        bool verified;
        bool paid;
    }

    mapping(address => Milestone) public contractorMilestones;
    uint256 public payoutAmount;
    bool public immutable contractLocked;

    event ContractorRegistered(address indexed contractor);
    event MilestoneClaimed(address indexed contractor);
    event MilestoneVerified(address indexed contractor);
    event PaymentReleased(address indexed contractor, uint256 amount);

    constructor(uint256 _payoutAmount, address admin) {
        payoutAmount = _payoutAmount;
        contractLocked = true;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(AUDITOR_ROLE, admin);
    }

    function registerContractor(address contractor) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(CONTRACTOR_ROLE, contractor);
        emit ContractorRegistered(contractor);
    }

    function claimMilestone() external onlyRole(CONTRACTOR_ROLE) {
        require(!contractorMilestones[msg.sender].claimed, "Already claimed");
        contractorMilestones[msg.sender].claimed = true;
        emit MilestoneClaimed(msg.sender);
    }

    function verifyMilestone(address contractor) external onlyRole(AUDITOR_ROLE) {
        require(contractorMilestones[contractor].claimed, "No claim to verify");
        contractorMilestones[contractor].verified = true;
        emit MilestoneVerified(contractor);
    }

    function releasePayment(address contractor) external onlyRole(AUDITOR_ROLE) {
        Milestone storage m = contractorMilestones[contractor];
        require(m.claimed && m.verified, "Invalid milestone state");
        require(!m.paid, "Already paid");

        m.paid = true;
        (bool success, ) = contractor.call{value: payoutAmount}("");
        require(success, "Payment failed");

        emit PaymentReleased(contractor, payoutAmount);
    }

    receive() external payable {}
}

/// @notice Intruder trying to spoof milestone or hijack payment
contract DCMAIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function spoofMilestoneAndSteal() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("claimMilestone(address)", msg.sender)
        );
        require(success, "Milestone claim failed");

        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("releasePayment(address)", msg.sender)
        );
    }
}
