// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SafeAlgorithm {
    uint256 public maxAllowed = 100;
    uint256[] public values;

    event ValuesStored(address indexed sender, uint256 count);

    // Secure version: Enforce length and offload complexity
    function storeSorted(uint256[] memory sortedInput) public {
        require(sortedInput.length <= maxAllowed, "Too many values");
        for (uint256 i = 1; i < sortedInput.length; i++) {
            require(sortedInput[i] >= sortedInput[i - 1], "Not sorted");
        }

        values = sortedInput;
        emit ValuesStored(msg.sender, sortedInput.length);
    }

    function getValue(uint256 index) public view returns (uint256) {
        require(index < values.length, "Index out of bounds");
        return values[index];
    }
}
