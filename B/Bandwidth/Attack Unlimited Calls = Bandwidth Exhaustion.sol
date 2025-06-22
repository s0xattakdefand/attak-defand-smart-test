// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BandwidthVulnerable {
    string[] public logs;

    // ❌ No limit — attacker can fill logs and block execution
    function submitLog(string memory message) public {
        logs.push(message);
    }

    function getLogCount() public view returns (uint256) {
        return logs.length;
    }
}
