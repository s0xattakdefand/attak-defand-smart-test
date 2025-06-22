// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title MockZKVerifier - Simulates always-valid zk proof checks
contract MockZKVerifier {
    function verifyProof(bytes calldata, bytes32) external pure returns (bool) {
        return true;
    }
}
