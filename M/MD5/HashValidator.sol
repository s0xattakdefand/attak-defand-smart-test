// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IHashLib {
    function hash(bytes calldata input) external pure returns (bytes32);
}

contract HashValidator {
    IHashLib public currentHashLib;
    mapping(bytes32 => address) public committed;

    constructor(address initialLib) {
        currentHashLib = IHashLib(initialLib);
    }

    function switchHashLib(address newLib) external {
        currentHashLib = IHashLib(newLib);
    }

    function commit(bytes calldata input) external {
        bytes32 hash = currentHashLib.hash(input);
        require(committed[hash] == address(0), "Duplicate");
        committed[hash] = msg.sender;
    }

    function verify(bytes calldata input) external view returns (bool) {
        return committed[currentHashLib.hash(input)] != address(0);
    }
}
