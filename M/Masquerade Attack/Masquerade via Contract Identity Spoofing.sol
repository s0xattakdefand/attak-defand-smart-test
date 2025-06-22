// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title FakeOracle - Masquerades as a Chainlink-like price oracle
contract FakeOracle {
    int256 public fakePrice;
    address public attacker;

    constructor(int256 _price, address _attacker) {
        fakePrice = _price;
        attacker = _attacker;
    }

    function latestAnswer() external view returns (int256) {
        return fakePrice;
    }
}
