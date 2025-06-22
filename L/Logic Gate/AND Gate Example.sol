// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract AndGate {
    function access(bool isAdmin, bool isVerified) external pure returns (bool) {
        return isAdmin && isVerified;
    }
}
