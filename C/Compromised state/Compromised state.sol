// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CompromisedStateGuard
/// @notice Guards and detects compromised state in a critical system
contract CompromisedStateGuard {
    address public admin;
    address public treasury;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    bool public paused;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier notPaused() {
        require(!paused, "Paused due to compromise");
        _;
    }

    event CompromiseDetected(string reason);
    event StateRecovered(address newAdmin, address newTreasury);

    constructor(address _admin, address _treasury) {
        admin = _admin;
        treasury = _treasury;
    }

    function mint(address to, uint256 amount) external onlyAdmin notPaused {
        balances[to] += amount;
        totalSupply += amount;
        _checkInvariant();
    }

    function transfer(address to, uint256 amount) external notPaused {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        _checkInvariant();
    }

    function _checkInvariant() internal {
        uint256 computed = 0;
        // Sum balance of known actors only
        computed += balances[msg.sender];
        computed += balances[treasury];
        if (computed > totalSupply) {
            paused = true;
            emit CompromiseDetected("Invariant broken: balance sum > totalSupply");
        }
    }

    function recoverState(address newAdmin, address newTreasury) external onlyAdmin {
        admin = newAdmin;
        treasury = newTreasury;
        paused = false;
        emit StateRecovered(newAdmin, newTreasury);
    }
}
