// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AgencyDashboardStore — Tracks agency-wide summaries for dashboard visibility
contract AgencyDashboardStore {
    address public admin;

    struct DashboardItem {
        string category;        // e.g., "AFR", "RISK", "MILESTONE"
        string description;     // e.g., "Q1 Report", "Entropy Drift", "zkSim complete"
        string uri;             // IPFS/Arweave/URL to content
        bytes32 contentHash;    // keccak256 hash of full content
        uint256 timestamp;
    }

    DashboardItem[] public logs;

    event DashboardUpdated(uint256 indexed id, string category, string description);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function addLog(
        string calldata category,
        string calldata description,
        string calldata uri,
        bytes32 contentHash
    ) external onlyAdmin returns (uint256) {
        logs.push(DashboardItem(category, description, uri, contentHash, block.timestamp));
        uint256 id = logs.length - 1;
        emit DashboardUpdated(id, category, description);
        return id;
    }

    function getLog(uint256 id) external view returns (DashboardItem memory) {
        return logs[id];
    }

    function getLatestLogs(uint256 n) external view returns (DashboardItem[] memory) {
        uint256 total = logs.length;
        uint256 start = total > n ? total - n : 0;
        DashboardItem[] memory result = new DashboardItem[](total - start);
        for (uint256 i = 0; i < result.length; i++) {
            result[i] = logs[start + i];
        }
        return result;
    }

    function totalLogs() external view returns (uint256) {
        return logs.length;
    }
}
