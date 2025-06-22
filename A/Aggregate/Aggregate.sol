// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Aggregator — Tracks numeric value aggregation per address or session
contract Aggregator {
    uint256 public total;
    uint256 public count;

    mapping(address => uint256) public submitted;
    mapping(address => bool) public hasSubmitted;

    event ValueSubmitted(address indexed user, uint256 value);
    event AggregationComplete(uint256 total, uint256 count, uint256 average);

    function submitValue(uint256 value) external {
        require(!hasSubmitted[msg.sender], "Already submitted");
        submitted[msg.sender] = value;
        hasSubmitted[msg.sender] = true;
        total += value;
        count += 1;

        emit ValueSubmitted(msg.sender, value);
    }

    function finalizeAggregation() external view returns (uint256 average) {
        require(count > 0, "No submissions yet");
        return total / count;
    }

    function getSummary() external view returns (uint256 _total, uint256 _count, uint256 _avg) {
        _total = total;
        _count = count;
        _avg = count > 0 ? total / count : 0;
    }
}
