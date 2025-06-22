// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AsymptoticSimulator - Simulates pseudo-asymptotic reward distributions

contract AsymptoticSimulator {
    mapping(address => uint256) public scores;
    mapping(address => uint256) public claims;

    uint256 public totalActions;
    uint256 public rewardBase = 1e18; // Base unit reward

    /// User performs an action, gets reward with decreasing value
    function performAction() external {
        totalActions++;
        uint256 reward = rewardBase / totalActions; // asymptotic decay: O(1/n)
        scores[msg.sender] += reward;
        claims[msg.sender]++;
    }

    /// Returns the asymptotic score assigned to a user
    function getUserScore(address user) external view returns (uint256) {
        return scores[user];
    }

    /// Resets for testing or analysis
    function reset(address user) external {
        scores[user] = 0;
        claims[user] = 0;
        totalActions = 0;
    }
}
