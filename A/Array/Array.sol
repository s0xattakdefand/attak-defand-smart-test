// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ArrayManager {
    address public admin;

    uint256[3] public fixedArray; // Fixed-length array of size 3
    uint256[] public dynamicArray; // Dynamic-length array

    event AddedToArray(uint256 indexed value);
    event RemovedFromArray(uint256 indexed index);
    event ReplacedInArray(uint256 indexed index, uint256 newValue);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // --- Fixed Array Operations ---
    function setFixed(uint index, uint256 value) external onlyAdmin {
        require(index < fixedArray.length, "Index out of bounds");
        fixedArray[index] = value;
    }

    function getFixedArray() external view returns (uint256[3] memory) {
        return fixedArray;
    }

    // --- Dynamic Array Operations ---
    function addToDynamic(uint256 value) external onlyAdmin {
        require(dynamicArray.length < 100, "Max length reached");
        dynamicArray.push(value);
        emit AddedToArray(value);
    }

    function replaceInDynamic(uint index, uint256 value) external onlyAdmin {
        require(index < dynamicArray.length, "Index out of bounds");
        dynamicArray[index] = value;
        emit ReplacedInArray(index, value);
    }

    function removeFromDynamic(uint index) external onlyAdmin {
        require(index < dynamicArray.length, "Index out of bounds");
        dynamicArray[index] = dynamicArray[dynamicArray.length - 1]; // swap & pop
        dynamicArray.pop();
        emit RemovedFromArray(index);
    }

    function getDynamicArray() external view returns (uint256[] memory) {
        return dynamicArray;
    }

    // --- View-Only Utility ---
    function sumDynamicArray() external view returns (uint256 total) {
        for (uint i = 0; i < dynamicArray.length; i++) {
            total += dynamicArray[i];
        }
    }
}
