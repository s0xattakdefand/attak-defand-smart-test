// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CCSSConfigScorer {
    address public admin;

    struct ConfigScore {
        string label;            // e.g., "CCE-2023002: quorum"
        uint8 score;             // 0–100 (higher = more secure)
        uint8 priority;          // 1 (low) → 5 (critical)
        uint256 lastUpdated;
    }

    mapping(bytes32 => ConfigScore) public scores;
    bytes32[] public configKeys;

    event ConfigScored(bytes32 indexed key, string label, uint8 score, uint8 priority);
    event ConfigScoreUpdated(bytes32 indexed key, uint8 oldScore, uint8 newScore);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerConfigScore(
        string calldata label,
        uint8 score,
        uint8 priority
    ) external onlyAdmin returns (bytes32 key) {
        require(score <= 100 && priority > 0 && priority <= 5, "Invalid score or priority");

        key = keccak256(abi.encodePacked(label));
        require(scores[key].lastUpdated == 0, "Config already scored");

        scores[key] = ConfigScore(label, score, priority, block.timestamp);
        configKeys.push(key);

        emit ConfigScored(key, label, score, priority);
    }

    function updateScore(bytes32 key, uint8 newScore) external onlyAdmin {
        require(scores[key].lastUpdated > 0, "Score not found");
        require(newScore <= 100, "Score must be <= 100");

        uint8 oldScore = scores[key].score;
        scores[key].score = newScore;
        scores[key].lastUpdated = block.timestamp;

        emit ConfigScoreUpdated(key, oldScore, newScore);
    }

    function getConfigScore(bytes32 key) external view returns (string memory, uint8, uint8, uint256) {
        ConfigScore memory s = scores[key];
        return (s.label, s.score, s.priority, s.lastUpdated);
    }

    function getAllKeys() external view returns (bytes32[] memory) {
        return configKeys;
    }
}
