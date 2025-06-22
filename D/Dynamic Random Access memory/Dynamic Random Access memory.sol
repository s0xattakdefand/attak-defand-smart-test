// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DynamicRandomAccessMemoryAttackDefense - Full Attack and Defense Simulation for DRAM-Inspired Memory Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Memory Usage Contract (Attack Simulation)
contract InsecureMemoryContract {
    uint256[] public storedArray;

    function unsafePush(uint256 value) external {
        uint256[] memory tempArray = storedArray;
        tempArray.push(value); // BAD: Modifies memory, not storage
        // storedArray remains unchanged on-chain
    }

    function unsafeOverwrite(uint256 index, uint256 value) external {
        uint256[] memory tempArray = storedArray;
        require(index < tempArray.length, "Index out of bounds (in memory)");
        tempArray[index] = value;
        // Only memory copy modified; storage untouched
    }

    function getStoredArrayLength() external view returns (uint256) {
        return storedArray.length;
    }
}

/// @notice Secure Memory Usage Contract (Defense)
contract SecureMemoryContract {
    uint256[] public storedArray;

    function safePush(uint256 value) external {
        storedArray.push(value); // Directly modifies storage
    }

    function safeOverwrite(uint256 index, uint256 value) external {
        require(index < storedArray.length, "Index out of bounds (storage)");
        storedArray[index] = value; // Directly modifies storage
    }

    function boundedBatchPush(uint256[] calldata values) external {
        require(values.length <= 100, "Too many elements"); // Bound checking
        for (uint256 i = 0; i < values.length; i++) {
            storedArray.push(values[i]);
        }
    }

    function getStoredArray() external view returns (uint256[] memory) {
        return storedArray;
    }
}

/// @notice Attack contract simulating memory overflow abuse
contract MemoryOverflowIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryOverflow(uint256 largeIndex, uint256 value) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("unsafeOverwrite(uint256,uint256)", largeIndex, value)
        );
    }
}
