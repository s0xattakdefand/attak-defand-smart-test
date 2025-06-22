// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SelectorReverseMap {
    mapping(bytes4 => string) public abiGuess;

    event ABIResolved(bytes4 indexed selector, string name);

    function register(bytes4 selector, string calldata name) external {
        abiGuess[selector] = name;
        emit ABIResolved(selector, name);
    }

    function resolve(bytes4 selector) external view returns (string memory) {
        return abiGuess[selector];
    }
}
