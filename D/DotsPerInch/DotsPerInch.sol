// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DotsPerInch {
    function triggerStackTooDeepError(uint256 input) public pure returns (uint256) {
        uint256 result = input;
        
        // Use a loop to avoid excessive local variables
        for (uint256 i = 1; i <= 17; i++) {
            result += i;
        }

        return result;
    }
}