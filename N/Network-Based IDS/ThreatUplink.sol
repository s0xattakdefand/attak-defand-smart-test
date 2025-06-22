// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ThreatUplink {
    event ThreatLog(
        address indexed reporter,
        bytes4 indexed selector,
        string tag,
        string message,
        uint256 timestamp
    );

    function logThreat(bytes4 selector, string calldata tag, string calldata message) external {
        emit ThreatLog(msg.sender, selector, tag, message, block.timestamp);
    }
}
