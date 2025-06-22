// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * A naive contract with a leftover test config (owner set to a dev test address).
 * Attackers can exploit if that address is not the real admin or is compromised.
 */
contract NaiveConfig {
    // Hardcoded leftover from testing
    address public owner = 0x1234567890abcdef1234567890abcdef12345678;
    uint256 public feeRate; // not validated, set by test scripts

    function setFeeRate(uint256 newFee) external {
        // ❌ Attack: only 'owner' can call, but leftover address 
        // might be compromised or dev forgot to set real prod address
        require(msg.sender == owner, "Not owner");
        feeRate = newFee;
    }

    function getFeeRate() external view returns (uint256) {
        return feeRate;
    }
}
