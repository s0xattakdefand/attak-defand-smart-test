// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract XorGate {
    function flip(bool optionA, bool optionB) external pure returns (bool) {
        return (optionA && !optionB) || (!optionA && optionB);
    }
}
