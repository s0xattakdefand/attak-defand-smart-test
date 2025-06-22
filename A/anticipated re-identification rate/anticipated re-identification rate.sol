// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ARIRTracker {
    uint256 public reidThreshold = 3;

    struct AnonUsage {
        uint256 count;
        uint256 lastBlock;
        uint256 entropySum; // sum of selector entropy or metadata drift
    }

    mapping(bytes32 => AnonUsage) public anonProfile;
    mapping(bytes32 => bool) public flagged;

    event ActionLogged(bytes32 indexed anonId, uint256 count, uint256 entropy);
    event ARIRAlert(bytes32 indexed anonId, uint256 count, uint256 arirScore);

    function logAnonAction(bytes32 anonId, uint256 entropyScore) external {
        AnonUsage storage profile = anonProfile[anonId];
        profile.count += 1;
        profile.lastBlock = block.number;
        profile.entropySum += entropyScore;

        emit ActionLogged(anonId, profile.count, entropyScore);

        uint256 arirScore = profile.entropySum / profile.count;
        if (profile.count >= reidThreshold && arirScore < 32) { // entropy too low = high re-ID risk
            flagged[anonId] = true;
            emit ARIRAlert(anonId, profile.count, arirScore);
        }
    }

    function isFlagged(bytes32 anonId) external view returns (bool) {
        return flagged[anonId];
    }

    function getProfile(bytes32 anonId) external view returns (AnonUsage memory) {
        return anonProfile[anonId];
    }

    function setThreshold(uint256 newThreshold) external {
        reidThreshold = newThreshold;
    }
}
