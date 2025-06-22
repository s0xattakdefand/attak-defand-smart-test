// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IVault {
    function withdraw() external;
}

contract VaultMOETracker {
    struct Metrics {
        uint256 totalAccesses;
        uint256 blockedAttempts;
        uint256 lastFailure;
    }

    mapping(address => Metrics) public vaultStats;

    function reportAccess(address vault, bool blocked) external {
        Metrics storage m = vaultStats[vault];
        m.totalAccesses++;
        if (blocked) {
            m.blockedAttempts++;
            m.lastFailure = block.timestamp;
        }
    }

    function getStats(address vault) external view returns (Metrics memory) {
        return vaultStats[vault];
    }
}
