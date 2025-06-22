// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract OrGate {
    function unlock(bool hasKey, bool knowsPassword) external pure returns (bool) {
        return hasKey || knowsPassword;
    }
}
