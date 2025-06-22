// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BootSafeInitializer {
    address public owner;
    bool public initialized;

    event BootInitialized(address indexed user);

    modifier notInitialized() {
        require(!initialized, "Already initialized");
        _;
    }

    function initialize(address _owner) public notInitialized {
        require(_owner != address(0), "Invalid owner");
        owner = _owner;
        initialized = true;

        emit BootInitialized(_owner);
    }
}
