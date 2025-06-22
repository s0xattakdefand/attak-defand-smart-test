// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CompromiseRegistry {
    address public admin;
    mapping(address => bool) public compromised;
    event Compromised(address indexed key);
    event Recovered(address indexed key);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function markCompromised(address user) external onlyAdmin {
        compromised[user] = true;
        emit Compromised(user);
    }

    function unmark(address user) external onlyAdmin {
        compromised[user] = false;
        emit Recovered(user);
    }

    function isSafe(address user) external view returns (bool) {
        return !compromised[user];
    }
}

contract CompromiseGuardedSystem {
    address public owner;
    CompromiseRegistry public registry;
    bool public paused;

    event CriticalActionExecuted(address indexed by);
    event Paused();
    event Unpaused();

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        require(!registry.compromised(msg.sender), "Compromised key");
        _;
    }

    modifier notPaused() {
        require(!paused, "Paused");
        _;
    }

    constructor(address _registry) {
        owner = msg.sender;
        registry = CompromiseRegistry(_registry);
    }

    function criticalAction() external onlyOwner notPaused {
        emit CriticalActionExecuted(msg.sender);
        // Do critical stuff...
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused();
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused();
    }

    function rotateOwner(address newOwner) external onlyOwner {
        require(!registry.compromised(newOwner), "New owner compromised");
        owner = newOwner;
    }
}
