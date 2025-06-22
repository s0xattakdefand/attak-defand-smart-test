// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// ATPGuard — Advanced Threat Protection Smart Contract Firewall
contract ATPGuard {
    address public admin;
    bool public paused;

    mapping(address => uint256) public riskScore;
    mapping(address => bool) public flagged;

    event ThreatDetected(address indexed actor, uint256 score, string reason);
    event ContractPaused();
    event ContractUnpaused();

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    modifier notPaused() {
        require(!paused, "Contract is paused due to threat");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Analyze payload, compute entropy risk, auto-mitigate if needed
    function analyze(bytes calldata payload, string calldata reason) external notPaused {
        uint256 score = entropy(payload);
        riskScore[msg.sender] += score;

        if (riskScore[msg.sender] >= 100 && !flagged[msg.sender]) {
            flagged[msg.sender] = true;
            paused = true;
            emit ThreatDetected(msg.sender, score, reason);
            emit ContractPaused();
        }
    }

    /// Simulate entropy score (simple hash-based heuristic)
    function entropy(bytes memory input) public pure returns (uint256) {
        bytes32 h = keccak256(input);
        uint256 score;
        for (uint256 i = 0; i < 32; i++) {
            if (uint8(h[i]) % 2 == 1) score++;
        }
        return score;
    }

    function unpause() external onlyAdmin {
        paused = false;
        emit ContractUnpaused();
    }

    function isFlagged(address actor) external view returns (bool) {
        return flagged[actor];
    }
}
