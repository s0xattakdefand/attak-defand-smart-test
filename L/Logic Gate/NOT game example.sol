// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract NotGate {
    function blockIfBlacklisted(bool isBlacklisted) external pure returns (bool) {
        return !isBlacklisted;
    }
}
