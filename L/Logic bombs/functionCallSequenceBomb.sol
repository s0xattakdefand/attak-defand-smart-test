// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SequenceLogicBomb {
    bool private stepOneDone = false;
    bool private stepTwoDone = false;

    function stepOne() external {
        stepOneDone = true;
    }

    function stepTwo() external {
        require(stepOneDone, "Step one not done");
        stepTwoDone = true;
    }

    function detonate() external {
        require(stepTwoDone, "Step two not done");
        selfdestruct(payable(msg.sender)); // 💣 Logic bomb only after perfect sequence
    }
}
