// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract AnalyticSystem is AccessControl {
    bytes32 public constant ANALYST_ROLE = keccak256("ANALYST_ROLE");

    struct Analytics {
        uint256 totalCalls;
        uint256 totalGas;
        uint256 lastCall;
        uint8    avgRisk;
    }

    // selector → user → analytics data
    mapping(bytes4 => mapping(address => Analytics)) public analyticsData;

    event Analyzed(address indexed user, bytes4 indexed selector, uint256 gasUsed, uint8 risk);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ANALYST_ROLE, msg.sender);
    }

    /// @notice Log analytic event per user/function
    function logAnalytics(address user, bytes4 selector, uint256 gasUsed, uint8 risk)
        external onlyRole(ANALYST_ROLE)
    {
        require(risk <= 100, "Risk score out of bounds");

        Analytics storage data = analyticsData[selector][user];
        data.totalCalls += 1;
        data.totalGas += gasUsed;
        data.lastCall = block.timestamp;

        // Weighted average risk update
        data.avgRisk = uint8((data.avgRisk * (data.totalCalls - 1) + risk) / data.totalCalls);

        emit Analyzed(user, selector, gasUsed, risk);
    }

    /// @notice Get summary analytics for a user+selector
    function getAnalytics(address user, bytes4 selector) external view returns (Analytics memory) {
        return analyticsData[selector][user];
    }

    /// @notice Check if user-selector pair is flagged
    function isFlagged(address user, bytes4 selector, uint8 riskThreshold) external view returns (bool) {
        return analyticsData[selector][user].avgRisk >= riskThreshold;
    }
}
