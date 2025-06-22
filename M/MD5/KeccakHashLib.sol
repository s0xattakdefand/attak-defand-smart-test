// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract KeccakHashLib {
    function hash(bytes calldata input) external pure returns (bytes32) {
        return keccak256(input);
    }
}
