// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ZeroDayTracker {
    mapping(bytes4 => bool) public seen;
    mapping(bytes4 => uint256) public firstSeenBlock;

    event ZeroDay(bytes4 selector, uint256 timestamp, uint256 blockNumber);

    fallback() external payable {
        bytes4 sel;
        assembly { sel := calldataload(0) }

        if (!seen[sel]) {
            seen[sel] = true;
            firstSeenBlock[sel] = block.number;
            emit ZeroDay(sel, block.timestamp, block.number);
        }
    }
}
