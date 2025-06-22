// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BaseAccess — Inheritable access and status control
abstract contract BaseAccess {
    address public owner;
    bool public paused;

    event Paused(bool status);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Access denied: Not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function togglePause(bool _paused) external onlyOwner {
        paused = _paused;
        emit Paused(_paused);
    }
}
