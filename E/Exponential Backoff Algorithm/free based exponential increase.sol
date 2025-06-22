// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Instead of time-based backoff, we do a cost-based approach:
 * Each new attempt from the same user requires a higher fee (exponentially).
 */
contract FeeExponentialBackoff {
    mapping(address => uint256) public attemptCount;
    uint256 public baseFee = 0.001 ether;
    uint256 public factor = 2;

    function doAction() external payable {
        uint256 needed = baseFee * (factor ** attemptCount[msg.sender]);
        require(msg.value >= needed, "Fee too low");
        attemptCount[msg.sender]++;
        // do something
    }
}
