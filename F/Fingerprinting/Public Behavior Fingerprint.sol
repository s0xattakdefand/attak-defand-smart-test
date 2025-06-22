// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PublicFingerprintTracker {
    mapping(address => uint256) public callFrequency;
    mapping(address => uint256) public lastCall;

    function access() external {
        callFrequency[msg.sender]++;
        lastCall[msg.sender] = block.timestamp;
    }

    function fingerprint(address user) external view returns (uint256 freq, uint256 last) {
        return (callFrequency[user], lastCall[user]);
    }
}
