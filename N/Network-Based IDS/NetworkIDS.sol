// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract NetworkIDS {
    mapping(bytes4 => uint256) public callCounts;
    mapping(bytes4 => uint256) public failCounts;
    mapping(bytes4 => bool) public flaggedSelectors;

    event IDSAlert(address indexed origin, bytes4 selector, string reason);

    function monitor(address target, bytes calldata data) external {
        bytes4 sel;
        assembly { sel := calldataload(data.offset) }
        callCounts[sel]++;

        (bool ok, ) = target.call(data);
        if (!ok) {
            failCounts[sel]++;
            if (failCounts[sel] * 10000 / callCounts[sel] > 5000) { // >50% fail
                flaggedSelectors[sel] = true;
                emit IDSAlert(msg.sender, sel, "High failure rate");
            }
        }
    }
}
