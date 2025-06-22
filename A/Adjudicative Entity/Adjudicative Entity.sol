// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Adjudicative Entity — Onchain Dispute Resolver
contract AdjudicativeEntity {
    enum ClaimStatus { Pending, Approved, Rejected }

    struct Claim {
        address claimant;
        string evidence;
        uint256 submittedAt;
        ClaimStatus status;
    }

    address public admin;
    uint256 public claimCounter;
    mapping(uint256 => Claim) public claims;

    event ClaimSubmitted(uint256 indexed id, address indexed claimant, string evidence);
    event ClaimResolved(uint256 indexed id, ClaimStatus status);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function submitClaim(string calldata evidence) external returns (uint256 claimId) {
        claimId = ++claimCounter;
        claims[claimId] = Claim(msg.sender, evidence, block.timestamp, ClaimStatus.Pending);
        emit ClaimSubmitted(claimId, msg.sender, evidence);
    }

    function resolveClaim(uint256 claimId, bool approve) external onlyAdmin {
        Claim storage c = claims[claimId];
        require(c.status == ClaimStatus.Pending, "Already resolved");

        c.status = approve ? ClaimStatus.Approved : ClaimStatus.Rejected;
        emit ClaimResolved(claimId, c.status);
    }

    function getClaim(uint256 claimId) external view returns (Claim memory) {
        return claims[claimId];
    }
}
