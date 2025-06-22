// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentTimelinessTracker - Manage expiry and freshness of Web3 protocol assessments

contract AssessmentTimelinessTracker {
    address public admin;

    struct Timeliness {
        bytes32 resultId;
        address target;
        uint256 assessedAt;
        uint256 expiresAt;
        string reason;
        bool invalidated;
    }

    mapping(bytes32 => Timeliness) public timelinessRecords;
    bytes32[] public trackedResults;

    event TimelinessRecorded(bytes32 indexed resultId, uint256 expiresAt);
    event TimelinessInvalidated(bytes32 indexed resultId, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function trackResult(
        bytes32 resultId,
        address target,
        uint256 assessedAt,
        uint256 expiresInSeconds,
        string calldata reason
    ) external onlyAdmin {
        require(timelinessRecords[resultId].assessedAt == 0, "Already tracked");
        uint256 expiresAt = assessedAt + expiresInSeconds;

        timelinessRecords[resultId] = Timeliness({
            resultId: resultId,
            target: target,
            assessedAt: assessedAt,
            expiresAt: expiresAt,
            reason: reason,
            invalidated: false
        });

        trackedResults.push(resultId);
        emit TimelinessRecorded(resultId, expiresAt);
    }

    function invalidateResult(bytes32 resultId, string calldata reason) external onlyAdmin {
        require(timelinessRecords[resultId].assessedAt != 0, "Result not tracked");
        timelinessRecords[resultId].invalidated = true;
        timelinessRecords[resultId].reason = reason;
        emit TimelinessInvalidated(resultId, reason);
    }

    function isResultFresh(bytes32 resultId) external view returns (bool) {
        Timeliness memory t = timelinessRecords[resultId];
        return !t.invalidated && block.timestamp <= t.expiresAt;
    }

    function getAllTrackedResults() external view returns (bytes32[] memory) {
        return trackedResults;
    }

    function getTimeliness(bytes32 resultId) external view returns (Timeliness memory) {
        return timelinessRecords[resultId];
    }
}
