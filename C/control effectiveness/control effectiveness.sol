// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EffectivenessValidator {
    address public owner;
    bool public paused;

    mapping(address => bool) public admins;

    event AdminAdded(address indexed admin);
    event ContractPaused(bool paused);
    event CriticalAction(address indexed triggeredBy, string action);

    modifier onlyOwner() {
        require(msg.sender == owner, "Access denied: Not owner");
        _;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Access denied: Not admin");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Action blocked: Contract paused");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// 🔧 Access Control Effectiveness: Can only owner add admins?
    function addAdmin(address admin) external onlyOwner {
        admins[admin] = true;
        emit AdminAdded(admin);
    }

    /// 🔧 Status Enforcement Effectiveness: Does pause block logic?
    function togglePause(bool _paused) external onlyOwner {
        paused = _paused;
        emit ContractPaused(_paused);
    }

    /// 🔧 Critical Function with Full Control Stack
    function executeCriticalAction(string calldata description)
        external
        onlyAdmin
        whenNotPaused
    {
        emit CriticalAction(msg.sender, description);
        // Sensitive logic here
    }
}
