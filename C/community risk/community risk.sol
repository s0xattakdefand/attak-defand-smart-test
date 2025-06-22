// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommunityRiskRegistry {
    address public admin;

    struct ActorRisk {
        string label;               // e.g., "VaultManager", "DAO Voter"
        uint8 riskScore;            // 0 (safe) → 100 (critical risk)
        string reason;
        uint256 updatedAt;
    }

    mapping(address => ActorRisk) public actorRisks;
    address[] public trackedActors;

    event RiskUpdated(address indexed actor, uint8 newScore, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function updateRisk(address actor, uint8 score, string calldata reason) external onlyAdmin {
        require(score <= 100, "Score too high");
        if (actorRisks[actor].updatedAt == 0) {
            trackedActors.push(actor);
        }

        actorRisks[actor] = ActorRisk({
            label: actorRisks[actor].label,
            riskScore: score,
            reason: reason,
            updatedAt: block.timestamp
        });

        emit RiskUpdated(actor, score, reason);
    }

    function setLabel(address actor, string calldata label) external onlyAdmin {
        actorRisks[actor].label = label;
    }

    function getRisk(address actor) external view returns (ActorRisk memory) {
        return actorRisks[actor];
    }

    function getAllTracked() external view returns (address[] memory) {
        return trackedActors;
    }
}
