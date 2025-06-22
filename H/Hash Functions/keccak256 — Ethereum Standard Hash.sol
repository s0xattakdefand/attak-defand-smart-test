// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Keccak256Example {
    function getHash(string memory input) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(input));
    }
}
