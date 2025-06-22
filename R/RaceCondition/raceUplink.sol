// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract RaceUplink {
    event RaceLog(string category, address indexed origin, bytes4 selector, uint256 blockNum, string note);

    function log(string calldata cat, bytes4 sel, string calldata note) external {
        emit RaceLog(cat, tx.origin, sel, block.number, note);
    }
}
