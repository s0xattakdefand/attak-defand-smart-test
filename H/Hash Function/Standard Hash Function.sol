// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract KeccakHasher {
    function hashString(string memory input) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(input));
    }
}
