// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Vulnerable to flooding: Anyone can call `claim()` repeatedly.
 */
contract UnrestrictedFloodTarget {
    mapping(address => uint256) public claims;

    function claim() external {
        claims[msg.sender]++;
    }
}
