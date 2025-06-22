// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NoFirewall {
    uint256 public secret;

    function setSecret(uint256 _value) external {
        secret = _value;
    }
}
