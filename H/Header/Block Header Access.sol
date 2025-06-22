// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BlockHeaderRead {
    function getHeader() external view returns (uint256 blockNum, uint256 timestamp, uint256 gasLimit) {
        return (block.number, block.timestamp, block.gaslimit);
    }
}
