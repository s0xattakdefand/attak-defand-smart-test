// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NaiveHardcodedConfig {
    address public owner = 0x1234567890abcdef1234567890abcdef12345678;
    uint256 public param;

    function setParam(uint256 newVal) external {
        require(msg.sender == owner, "Not owner");
        param = newVal;
    }
}
