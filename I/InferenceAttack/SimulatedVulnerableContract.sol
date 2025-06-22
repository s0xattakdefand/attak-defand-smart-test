// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract HiddenLogic {
    uint256 private secretValue = 42;

    function guess(uint256 input) external returns (bool) {
        if (input == secretValue) {
            emit CorrectGuess(msg.sender);
            return true;
        }
        return false;
    }

    event CorrectGuess(address user);
}
