// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Anti-flood system: Requires ETH payment per call to discourage spam.
 */
contract FeeBasedThrottle {
    uint256 public fee = 0.01 ether;
    address public treasury;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function callWithFee() external payable {
        require(msg.value >= fee, "Insufficient fee");
        payable(treasury).transfer(msg.value);
        // Proceed with sensitive logic
    }
}
