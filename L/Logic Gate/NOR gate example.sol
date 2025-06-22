// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract NorGate {
    function denyIfAnyTrue(bool condA, bool condB) external pure returns (bool) {
        return !(condA || condB);
    }
}
