// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SafeCellMemory {
    function manipulateCell(bytes memory input) public pure returns (uint256) {
        require(input.length >= 32, "Not enough data");
        uint256 extracted;
        assembly {
            // read first 32 bytes from input into 'extracted'
            extracted := mload(add(input, 32))
        }
        return extracted;
    }
}
